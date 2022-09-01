import json
import uuid
import random
import bcrypt
import psycopg2.extras
import rtlib
import yenot.backend.api as api
import yenotauth.core
from . import messaging
from . import avatars

app = api.get_global_app()


def user_sidebar(idcolumn):
    return [{"name": "user_general", "on_highlight_row": {"id": idcolumn}}]


# NOTE & TODO - Many end-points here come in 2 variants as (1) the admin
# version "/api/user/<userid>" and (2) the user version "/api/user/me".  It is
# imperative that the user version be declared before the admin version to the
# URL router.  For decorators, that means the user version needs to come
# _last_.


@app.put("/api/user/me", name="put_api_user_me")
def put_api_user_me(request):
    user = api.table_from_tab2(
        "user",
        amendments=["id"],
        options=[
            "full_name",
            "password",
            "descr",
        ],
    )

    if len(user.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one user required.")

    with app.dbconn() as conn:
        active = api.active_user(conn)

        columns = []
        for c in user.DataRow.__slots__:
            if c == "password":
                columns.append("pwhash")
            else:
                columns.append(c)

        tt = rtlib.simple_table(columns)
        for row in user.rows:
            with tt.adding_row() as r2:
                for c in user.DataRow.__slots__:
                    if c == "id":
                        r2.id = active.id
                    elif c == "password":
                        hashed = bcrypt.hashpw(
                            row.password.encode("utf8"), bcrypt.gensalt()
                        )
                        hashed = hashed.decode("ascii")
                        r2.pwhash = hashed
                    else:
                        setattr(r2, c, getattr(row, c))

        with api.writeblock(conn) as w:
            w.update_rows("users", tt)

        conn.commit()
    return api.Results().json_out()


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
            "avatar",
            "roles",
        ],
        matrix=["roles"],
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

    with app.dbconn() as conn:
        is_new = not update_existing or 0 == api.sql_1row(
            conn, "select count(*) from users where id=%(uid)s", {"uid": userid}
        )

        columns = []
        for c in user.DataRow.__slots__:
            if c == "password":
                columns.append("pwhash")
            elif c == "pin":
                columns.append("pinhash")
            else:
                columns.append(c)
        if is_new:
            columns.append("avatar")

        tt = rtlib.simple_table(columns)
        # TODO: in-elegant table transformation code for matrix columns
        tt.matrices = user.matrices
        for row in user.rows:
            with tt.adding_row() as r2:
                for c in user.DataRow.__slots__:
                    if c == "password" and row.password is not None:
                        hashed = bcrypt.hashpw(
                            row.password.encode("utf8"), bcrypt.gensalt()
                        )
                        hashed = hashed.decode("ascii")
                        r2.pwhash = hashed
                    elif c == "pin" and row.pin is not None:
                        hashed = bcrypt.hashpw(row.pin.encode("utf8"), bcrypt.gensalt())
                        hashed = hashed.decode("ascii")
                        r2.pinhash = hashed
                    elif c == "username":
                        r2.username = row.username.upper()
                    else:
                        setattr(r2, c, getattr(row, c))
                if is_new:
                    colorset = random.choice(avatars.COLORS)
                    source = getattr(row, "username")
                    if getattr(row, "full_name"):
                        source = "".join([x[0] for x in row.full_name.split(" ")])
                    initials = (source[0] + source[-1]).upper()
                    print(f"creating an avatar with initials {initials}")
                    r2.avatar = avatars.construct_avatar(initials, *colorset)

        with api.writeblock(conn) as w:
            w.upsert_rows("users", tt, matrix={"roles": "userroles"})
            w.upsert_rows("addresses", addresses)

        conn.commit()
    return api.Results().json_out()


@app.get("/api/user/me", name="get_api_user_me_record")
def get_api_user_record_me():
    with app.dbconn() as conn:
        active = api.active_user(conn)

    return _get_api_user_record(active.id, admin=False)


@app.get("/api/user/me/avatar.png", name="get_api_user_me_avatar")
def get_api_user_me_avatar(response):
    with app.dbconn() as conn:
        active = api.active_user(conn)

        avatar_bytes = api.sql_1row(
            conn, "select avatar from users where id=%(uid)s", {"uid": active.id}
        )
        if avatar_bytes:
            avatar_bytes = bytes(avatar_bytes)

    response.content_type = "image/png"
    return avatar_bytes


@app.get("/api/user/<userid>", name="get_api_user_record")
def get_api_user_record(userid):
    return _get_api_user_record(userid if userid != "new" else None, admin=True)


def _get_api_user_record(userid, admin):
    select = """
select users.id, users.username, full_name, descr,
    inactive,
    pinhash is not null as has_pin,
    null as password,
    null as pin,
    (
        select array_agg(userroles.roleid::text) from userroles where userroles.userid=users.id
    ) as roles
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
    devicetokens.id,
    devicetokens.inactive, devicetokens.device_name,
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
            roles=api.cgen.matrix(),
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

        if admin:
            cm = api.ColumnMap(
                id=api.cgen.yenot_role.surrogate(),
                role_name=api.cgen.yenot_role.name(
                    label="Role", url_key="id", represents=True
                ),
            )
            select_role_univ = "select * from roles order by roles.sort"
            results.tables["roles:universe"] = api.sql_tab2(
                conn, select_role_univ, None, cm
            )

        cm = api.ColumnMap(
            id=api.cgen.device_token.surrogate(),
            device_name=api.cgen.device_token.name(),
        )
        results.tables["devicetokens"] = api.sql_tab2(
            conn, selectdev, {"uid": userid}, cm
        )

        cm = api.ColumnMap(
            id=api.cgen.user_session.surrogate(),
            ipaddress=api.cgen.auto(label="IP Address"),
            pin_2fa=api.cgen.auto(hidden=True),
        )
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


@app.get("/api/user/<userid>/address/<addrid>", name="get_api_user_address")
@app.get("/api/user/me/address/<addrid>", name="get_api_user_me_address")
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


def _raise_payload_match(row, attr, urlvalue):
    value = getattr(row, attr, None)
    if value and value != urlvalue:
        raise api.UserError(
            "invalid-input",
            "The provided user record has a record id which does not match the URL.",
        )


@app.put("/api/user/me/address/<addrid>", name="put_api_user_me_address")
def put_api_user_me_address(request, addrid):
    with app.dbconn() as conn:
        active = api.active_user(conn)

    return _put_api_user_address(request, active.id, addrid, admin=False)


@app.put("/api/user/<userid>/address/<addrid>", name="put_api_user_address")
def put_api_user_address(request, userid, addrid):
    return _put_api_user_address(request, userid, addrid, admin=True)


def _put_api_user_address(request, userid, addrid, admin):
    extra = []
    if admin:
        extra.append("is_verified")

    address = api.table_from_tab2(
        "address",
        amendments=["id", "userid"],
        options=["addr_type", "address", "is_primary", "is_2fa_target", *extra],
    )

    _raise_payload_match(address.rows[0], "id", addrid)
    _raise_payload_match(address.rows[0], "userid", userid)

    address.rows[0].id = addrid
    address.rows[0].userid = userid

    with app.dbconn() as conn:
        select = "select count(*) from addresses where userid=%(uid)s and id=%(aid)s"
        exists = api.sql_1row(conn, select, {"uid": userid, "aid": addrid})

        if not admin and exists > 0:
            banned = ["addr_type", "address"]
            # Ordinary user cannot edit addr_type & address after the
            # fact due to verification requirements.
            included = set(banned).difference(address.DataRow.__slots__)
            if len(included) > 0:
                name = "address"
                raise api.UserError(
                    "invalid-collection",
                    f'Post file "{name}" contains incorrect data.  Fields {included} cannot be updated after the address is added.',
                )

        with api.writeblock(conn) as w:
            w.upsert_rows("addresses", address)
        conn.commit()

        if not admin:
            _send_verify(conn, request, userid, addrid)

    return api.Results().json_out()


@app.put(
    "/api/user/me/address/<addrid>/send-verify",
    name="put_api_user_me_address_send_verify",
)
def put_api_user_address_me_send_verify(request, addrid):
    with app.dbconn() as conn:
        active = api.active_user(conn)
        _send_verify(conn, request, active.id, addrid)

    return api.Results().json_out()


@app.put(
    "/api/user/<userid>/address/<addrid>/send-verify",
    name="put_api_user_address_send_verify",
)
def put_api_user_address_send_verify(userid, addrid):
    with app.dbconn() as conn:
        _send_verify(conn, userid, addrid)

    return api.Results().json_out()


def _send_verify(conn, request, userid, addrid):
    update = """
update addresses set verify_hash=%(vhash)s
where id=%(aid)s and userid=%(uid)s
returning id, userid, addr_type, address
"""

    # TODO: consider a verify_expire column on the address so that verify
    # codes have a (short) lifetime
    verify = yenotauth.core.generate_pin6()

    hashed = bcrypt.hashpw(verify.encode("utf8"), bcrypt.gensalt())
    hashed = hashed.decode("ascii")

    params = {"uid": userid, "aid": addrid, "vhash": hashed}
    target = api.sql_1object(conn, update, params)
    conn.commit()

    messaging.communicate_verify(target, target.userid, request, target.id, verify)


@app.put("/api/user/me/address/<addrid>/verify", name="put_api_user_me_address_verify")
def put_api_user_me_address_verify(request, addrid):
    confirmation = request.params.get("confirmation")

    select = """
select verify_hash
from addresses
where id=%(aid)s and userid=%(uid)s
"""

    update = """
update addresses set is_verified=true
where id=%(aid)s and userid=%(uid)s
"""

    with app.dbconn() as conn:
        active = api.active_user(conn)

        params = {"uid": active.id, "aid": addrid}
        vhash = api.sql_1row(conn, select, params)

        if not bcrypt.checkpw(confirmation.encode("utf8"), vhash.encode("utf8")):
            raise api.UserError("invalid-password", "Verification PIN does not match.")

        api.sql_void(conn, update, params)
        conn.commit()

    return api.Results().json_out()


@app.delete("/api/user/me/address/<addrid>", name="delete_api_user_me_address")
def delete_api_user_me_address(addrid):
    delete = """
delete from addresses where userid=%(uid)s and id=%(aid)s;
"""

    with app.dbconn() as conn:
        active = api.active_user(conn)

        api.sql_void(conn, delete, {"uid": active.id, "aid": addrid})
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
