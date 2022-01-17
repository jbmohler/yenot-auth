import json
import uuid
import bcrypt
import psycopg2.extras
import rtlib
import yenot.backend.api as api
import yenotauth.core

app = api.get_global_app()


def user_sidebar(idcolumn):
    return [{"name": "user_general", "on_highlight_row": {"id": idcolumn}}]


@app.put("/api/user/<userid>", name="put_api_user")
@app.post("/api/user", name="post_api_user")
def post_api_user(request, userid=None):
    user = api.table_from_tab2(
        "user",
        amendments=["id"],
        options=[
            "username",
            "full_name",
            "password",
            "pin",
            "inactive",
            "descr",
            "roles",
            "roles_add",
            "roles_del",
        ],
    )
    addresses = api.table_from_tab2(
        "addresses",
        default_missing=True,
        amendments=["id", "userid"],
        options=["addr_type", "address", "is_primary", "is_2fa_target"],
    )

    if len(user.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one user required.")

    update_existing = request.route.method == "PUT"
    if update_existing:
        if user.rows[0].id not in (None, userid):
            raise api.UserError(
                "invalid-input",
                "The provided user record has a record id which does not match the URL.",
            )

        for row in user.rows:
            row.id = userid

    for addr in addresses.rows:
        if getattr(addr, "userid") is None and userid is None:
            raise api.UserError(
                "invalid-input",
                "If userid is not specified in URL then no addresses can be upserted",
            )

        # no conditionals, ensure that these addresses are linked
        # explicitly to the unique user being inserted/updated
        addr.userid = userid

    insroles = """
insert into userroles (userid, roleid)
select (select id from users where username=%(un)s), rl.rl::uuid
from unnest(%(roles)s) rl"""
    delroles = """
with roles_del as (
    select unnest(%(roles)s::uuid[]) as r
)
delete from userroles
where userid=%(uid)s and roleid in (select r from roles_del)"""

    with app.dbconn() as conn:
        columns = []
        for c in user.DataRow.__slots__:
            if c == "password":
                columns.append("pwhash")
            elif c == "pin":
                columns.append("pinhash")
            elif c not in ("roles", "roles_add", "roles_del"):
                columns.append(c)

        tt = rtlib.simple_table(columns)
        for row in user.rows:
            with tt.adding_row() as r2:
                for c in user.DataRow.__slots__:
                    if c == "password":
                        hashed = bcrypt.hashpw(
                            row.password.encode("utf8"), bcrypt.gensalt()
                        )
                        hashed = hashed.decode("ascii")
                        r2.pwhash = hashed
                    elif c == "pin":
                        hashed = bcrypt.hashpw(row.pin.encode("utf8"), bcrypt.gensalt())
                        hashed = hashed.decode("ascii")
                        r2.pinhash = hashed
                    elif c == "username":
                        r2.username = row.username.upper()
                    else:
                        setattr(r2, c, getattr(row, c))

        with api.writeblock(conn) as w:
            w.upsert_rows("users", tt)
            w.upsert_rows("addresses", addresses)

        if "roles" in user.DataRow.__slots__ or "roles_add" in user.DataRow.__slots__:
            adds = "roles" if "roles" in user.DataRow.__slots__ else "roles_add"
            add_list = getattr(user.rows[0], adds)
            if add_list:
                api.sql_void(
                    conn, insroles, {"un": tt.rows[0].username, "roles": add_list}
                )
        if "roles_del" in user.DataRow.__slots__:
            if not update_existing:
                raise api.UserError(
                    "invalid-parameter", "Only allow role deletion on PUT variant"
                )
            if user.rows[0].roles_del:
                api.sql_void(
                    conn, delroles, {"uid": userid, "roles": user.rows[0].roles_del}
                )

        conn.commit()
    return api.Results().json_out()


@app.get("/api/user/me", name="get_api_user_me_record")
def get_api_user_record_me():
    with app.dbconn() as conn:
        active = api.active_user(conn)

    return _get_api_user_record(active.id)


@app.get("/api/user/<userid>", name="get_api_user_record")
def get_api_user_record(userid):
    return _get_api_user_record(userid if userid != "new" else None)


def _get_api_user_record(userid):
    select = """
select users.id, users.username, full_name, descr,
    inactive,
    pinhash is not null as has_pin,
    null as password,
    null as pin,
    (select array_agg(userroles.roleid::text) from userroles where userroles.userid=%(uid)s) as roles
from users
where users.id=%(uid)s
"""

    selectaddr = """
select id, addr_type, address, is_primary, is_2fa_target, is_verified
from addresses
where userid=%(uid)s
"""

    selectroles = """
select roles.id, roles.role_name, roles.sort
from roles
where roles.id in (
        select userroles.roleid from userroles where userroles.userid=%(uid)s
        )
order by roles.sort, roles.role_name;
"""

    selectsess = """
select
    sessions.id, sessions.inactive,
    sessions.ipaddress, sessions.pin_2fa,
    sessions.issued, sessions.expires,
    sessions.expires<current_timestamp as expired
from sessions
where sessions.userid=%(uid)s and sessions.expires>current_timestamp-interval '3 hours'
"""

    selectdev = """
select
    devicetokens.id, devicetokens.device_name,
    devicetokens.inactive,
    devicetokens.issued, devicetokens.expires,
    devicetokens.expires<current_timestamp as expired,
    x.last_session_expires
from devicetokens
left outer join lateral (
    select devicetokens.id, sessions.expires as last_session_expires
    from devicetokens
    join sessions on sessions.devtok_id=devicetokens.id
    left outer join sessions s2 on s2.devtok_id=devicetokens.id and s2.expires > sessions.expires
    where s2.devtok_id is null
    ) x on x.id=devicetokens.id
where devicetokens.userid=%(uid)s and devicetokens.expires>current_timestamp-interval '48 hours'
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(url_key="id", represents=True),
            has_pin=api.cgen.auto(skip_write=True),
            password=api.cgen.auto(),
            pin=api.cgen.auto(skip_write=userid != None),
            roles=api.cgen.stringlist(hidden=True),
        )
        cols, rows = api.sql_tab2(conn, select, {"uid": userid}, cm)

        if userid == None:

            def default_row(index, row):
                row.id = str(uuid.uuid1())
                # TODO: would be nice to default roles with the basic login
                # role, but that is not a universal knowable
                row.roles = []

            rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["user", True] = cols, rows

        results.tables["addresses"] = api.sql_tab2(conn, selectaddr, {"uid": userid})

        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
        )
        results.tables["roles"] = api.sql_tab2(conn, selectroles, {"uid": userid}, cm)

        cm = api.ColumnMap(
            id=api.cgen.device_token.surrogate(),
            device_name=api.cgen.device_token.name(),
        )
        results.tables["devicetokens"] = api.sql_tab2(
            conn, selectdev, {"uid": userid}, cm
        )

        cm = api.ColumnMap()
        results.tables["sessions"] = api.sql_tab2(conn, selectsess, {"uid": userid}, cm)
    return results.json_out()


@app.get("/api/user/me/address/new", name="get_api_user_me_address_new")
@app.get("/api/user/<userid>/address/new", name="get_api_user_address_new")
def get_api_user_address_new(userid=None):
    select = """
select id, addr_type, address, is_primary, is_2fa_target, is_verified
from addresses
where false;
"""

    results = api.Results()
    with app.dbconn() as conn:
        if userid is None:
            active = api.active_user(conn)
            userid = active.id

        cm = api.ColumnMap(
            id=api.cgen.yenot_user_address.surrogate(),
            is_verified=api.cgen.auto(skip_write=True),
        )
        cols, rows = api.sql_tab2(conn, select, column_map=cm)

        def default_row(index, row):
            row.id = str(uuid.uuid1())
            row.userid = userid
            row.is_primary = False
            row.is_2fa_target = False
            row.is_verified = False

        rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["address", True] = cols, rows
    return results.json_out()


@app.get("/api/user/me/address/<addrid>", name="get_api_user_me_address")
@app.get("/api/user/<userid>/address/<addrid>", name="get_api_user_address")
def get_api_user_address(userid=None, addrid=None):
    select = """
select id, addr_type, address, is_primary, is_2fa_target, is_verified
from addresses
where userid=%(uid)s and id=%(aid)s;
"""

    results = api.Results()
    with app.dbconn() as conn:
        if userid is None:
            active = api.active_user(conn)
            userid = active.id

        cm = api.ColumnMap(
            id=api.cgen.yenot_user_address.surrogate(),
            is_verified=api.cgen.auto(skip_write=True),
        )
        results.tables["address", True] = api.sql_tab2(
            conn, select, {"uid": userid, "aid": addrid}, cm
        )
    return results.json_out()


@app.put("/api/user/me/address/<addrid>", name="put_api_user_me_address")
@app.put("/api/user/<userid>/address/<addrid>", name="put_api_user_address")
def put_api_user_address(userid="me", addrid=None):
    address = api.table_from_tab2(
        "address",
        amendments=["id", "userid"],
        options=["addr_type", "address", "is_primary", "is_2fa_target"],
    )

    address.rows[0].id = addrid
    address.rows[0].userid = userid

    with app.dbconn() as conn:
        if userid == "me":
            active = api.active_user(conn)
            userid = active.id

        with api.writeblock(conn) as w:
            w.upsert_rows("addresses", address)
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/user/<userid>/address/<addrid>", name="delete_api_user_address")
def delete_api_user_address(userid, addrid):
    delete = """
delete from addresses where userid=%(uid)s and id=%(aid)s;
"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"uid": userid, "aid": addrid})
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/user/me/address/<addrid>", name="delete_api_user_me_address")
def delete_api_user_me_address(userid, addrid):
    delete = """
delete from addresses where userid=%(uid)s and id=%(aid)s;
"""

    with app.dbconn() as conn:
        active = api.active_user(conn)
        userid = active.id

        api.sql_void(conn, delete, {"uid": userid, "aid": addrid})
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/user/<userid>", name="delete_api_user_record")
def delete_api_user_record(userid):
    # consider using cascade
    delete = """
delete from userroles where userid=%(uid)s;
delete from sessions where userid=%(uid)s;
delete from addresses where userid=%(uid)s;
delete from users where id=%(uid)s;
"""

    with app.dbconn() as conn:
        active = api.active_user(conn)
        if active.id == userid:
            raise api.UserError(
                "data-validation",
                "The authenticated user cannot delete their own account.",
            )

        api.sql_void(conn, delete, {"uid": userid})
        conn.commit()
    return api.Results().json_out()


def _validate_oldpass(conn, oldpass):
    select = """
select id, username, pwhash, inactive
from users
where id=(select userid from sessions where sessions.id=%(sid)s)"""

    user = api.sql_1object(conn, select, {"sid": yenotauth.core.request_session_id()})

    if user == None:
        raise api.UserError(
            "invalid-user", "Cannot find the record for the password change"
        )
    if bcrypt.hashpw(
        oldpass.encode("utf8"), user.pwhash.encode("utf8")
    ) != user.pwhash.encode("utf8"):
        raise api.UserError("invalid-password", "old password does not match")

    return user


@app.post("/api/user/me/change-password", name="api_user_me_change_password")
def api_user_me_change_password(request):
    oldpass = request.forms.get("oldpass")
    newpass = request.forms.get("newpass")

    update = """
update users set pwhash=%(h)s where id=%(i)s"""

    with app.dbconn() as conn:
        user = _validate_oldpass(conn, oldpass)

        hashed = bcrypt.hashpw(newpass.encode("utf8"), bcrypt.gensalt())
        hashed = hashed.decode("ascii")

        api.sql_void(conn, update, {"h": hashed, "i": user.id})
        conn.commit()
    return api.Results().json_out()


@app.post("/api/user/me/change-pin", name="api_user_me_change_pin")
def api_user_me_change_pin(request):
    raise api.UserError("deprecated", "User PIN with 2fa is no longer supported")

    oldpass = request.forms.get("oldpass")
    newpin = request.forms.get("newpin")
    t2fa = json.loads(request.forms.get("target_2fa"))

    update = """
update users set pinhash=%(h)s, target_2fa=%(fa)s where id=%(i)s"""

    with app.dbconn() as conn:
        user = _validate_oldpass(conn, oldpass)

        hashed = bcrypt.hashpw(newpin.encode("utf8"), bcrypt.gensalt())
        hashed = hashed.decode("ascii")

        x = psycopg2.extras.Json(t2fa)
        api.sql_void(conn, update, {"h": hashed, "i": user.id, "fa": x})
        conn.commit()
    return api.Results().json_out()


def get_users_prompts():
    return api.PromptList(
        include_inactive=api.cgen.boolean(default=False),
        userrole=api.cgen.yenot_role.surrogate(label="Role"),
        __order__=["include_inactive", "userrole"],
    )


@app.get(
    "/api/users/list",
    name="get_api_users_list",
    report_title="User List",
    report_prompts=get_users_prompts,
    report_sidebars=user_sidebar("id"),
)
def get_users(request):
    iinactive = api.parse_bool(request.params.get("include_inactive", False))
    userrole = request.params.get("userrole", None)

    select = """
select users.id, users.username, users.full_name, 
    users.descr as description, users.inactive, 
    loggedin.count, userroles2.rolenames as roles
from users
left outer join (select userid, count(*) from sessions where not inactive group by userid) as loggedin on loggedin.userid=users.id
left outer join (
    select 
        userid, 
        array_agg(roles.role_name order by roles.sort) as rolenames
    from userroles 
    join roles on roles.id=userroles.roleid
    group by userid) as userroles2 on userroles2.userid=users.id
/*WHERE*/
order by users.username
"""

    wheres = []
    params = {}
    if userrole not in ("", None):
        wheres.append(
            "users.id in (select userroles.userid from userroles where userroles.roleid=%(ri)s)"
        )
        params["ri"] = userrole
    if not iinactive:
        wheres.append("not users.inactive")

    if len(wheres) > 0:
        select = select.replace("/*WHERE*/", "where " + " and ".join(wheres))

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(url_key="id", represents=True),
            count=api.cgen.auto(label="Active Sessions"),
            roles=api.cgen.stringlist(),
        )

        results.tables["users", True] = api.sql_tab2(conn, select, params, cm)
    return results.json_out()


@app.get(
    "/api/users/lastlogin",
    name="api_users_lastlogin",
    report_title="User List by Last Login",
    report_sidebars=user_sidebar("id"),
)
def get_users_lastlogin():
    select = """
select users.id, users.username, 
    lastlog.ipaddress, lastlog.issued, 
    active.count as active_count
from users
join lateral (
    select sessions.ipaddress, sessions.issued
    from sessions
    where sessions.userid=users.id
    order by issued desc
    limit 1) lastlog on true
left outer join lateral (
    select count(*)
    from sessions
    where sessions.userid=users.id and not sessions.inactive) as active on true
order by users.username"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(url_key="id", represents=True),
            ipaddress=api.cgen.auto(label="IP Address"),
            active_count=api.cgen.auto(label="Active Sessions"),
        )
        results.tables["logins", True] = api.sql_tab2(conn, select, column_map=cm)
    return results.json_out()
