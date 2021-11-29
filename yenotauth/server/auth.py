import os
import json
import uuid
import datetime
import random
import base64
import bcrypt
import psycopg2.extras
from bottle import request, response
import rtlib
import yenot.backend.api as api
import yenotauth.core

app = api.get_global_app()

CAPS_SELECT = """
select roles.role_name, activities.act_name
from sessions
join userroles on userroles.userid=sessions.userid
join roleactivities on roleactivities.roleid=userroles.roleid
join activities on activities.id=roleactivities.activityid
join roles on roles.id=userroles.roleid
where sessions.id=%(sid)s and roleactivities.permitted
"""


def user_sidebar(idcolumn):
    return [{"name": "user_general", "on_highlight_row": {"id": idcolumn}}]


def role_sidebar(idcolumn):
    return [{"name": "role_general", "on_highlight_row": {"id": idcolumn}}]


def activity_sidebar(idcolumn, namecolumn):
    return [
        {
            "name": "activity_general",
            "on_highlight_row": {"id": idcolumn, "act_name": namecolumn},
        }
    ]


@app.put("/api/user/<userid>", name="put_api_user")
@app.post("/api/user", name="post_api_user")
def post_api_user(userid=None):
    user = api.table_from_tab2(
        "user",
        amendments=["id"],
        options=[
            "username",
            "full_name",
            "password",
            "pin",
            "target_2fa",
            "inactive",
            "descr",
            "roles",
        ],
    )

    update_existing = request.route.method == "PUT"

    if len(user.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one user required.")

    insroles = """
insert into userroles (userid, roleid)
select (select id from users where username=%(un)s), rl.rl::uuid
from unnest(%(roles)s) rl"""

    with app.dbconn() as conn:
        columns = []
        for c in user.DataRow.__slots__:
            if c == "password":
                columns.append("pwhash")
            elif c == "pin":
                columns.append("pinhash")
            elif c != "roles":
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
                    elif c == "id" and getattr(row, "id", None) == None:
                        if update_existing:
                            r2.id = userid
                        else:
                            r2.id = None
                    elif c == "username":
                        r2.username = row.username.upper()
                    elif c == "target_2fa":
                        r2.target_2fa = psycopg2.extras.Json(row.target_2fa)
                    else:
                        setattr(r2, c, getattr(row, c))

        with api.writeblock(conn) as w:
            w.upsert_rows("users", tt)

        if "roles" in user.DataRow.__slots__:
            api.sql_void(
                conn, insroles, {"un": tt.rows[0].username, "roles": user.rows[0].roles}
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
    target_2fa
from users
where users.id=%(uid)s
"""

    selectroles = """
select roles.id, roles.role_name, roles.sort
from roles
where roles.id in (
        select userroles.roleid from userroles where userroles.userid=%(uid)s
        )
order by roles.sort, roles.role_name;
"""

    selectdev = """
select
    devicetokens.id, devicetokens.device_name,
    devicetokens.issued, devicetokens.expires,
    devicetokens.expires<current_timestamp as expired,
    x.last_session_refresh
from devicetokens
left outer join lateral (
    select devicetokens.id, sessions.refreshed as last_session_refresh
    from devicetokens
    join sessions on sessions.devtok_id=devicetokens.id
    left outer join sessions s2 on s2.devtok_id=devicetokens.id and s2.refreshed > sessions.refreshed
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
            password=api.cgen.auto(skip_write=userid != None),
            pin=api.cgen.auto(skip_write=userid != None),
        )
        cols, rows = api.sql_tab2(conn, select, {"uid": userid}, cm)

        if userid == None:

            def default_row(index, row):
                row.id = str(uuid.uuid1())

            rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["user", True] = cols, rows

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
    return results.json_out()


@app.delete("/api/user/<userid>", name="delete_api_user_record")
def delete_api_user_record(userid):
    # consider using cascade
    delete = """
delete from userroles where userid=%(uid)s;
delete from sessions where userid=%(uid)s;
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
def api_user_me_change_password():
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
def api_user_me_change_pin():
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


@app.post("/api/session", name="api_session", skip=["yenot-auth"])
def api_session():
    username = request.forms.get("username")
    password = request.forms.get("password", None)
    device_token = request.forms.get("device_token", None)
    ip = request.environ.get("REMOTE_ADDR")

    if not password and not device_token:
        raise api.UserError(
            "required-param",
            "You must specify either the user's password or a device token.",
        )

    select_user = "select id, username, pwhash as comphash, inactive from users where username=%(uname)s"
    select_devtok = """
select
    users.id, users.username, users.inactive,
    devicetokens.tokenhash as comphash, devicetokens.issued, devicetokens.expires
from devicetokens
join users on users.id=devicetokens.userid
where
    username=%(uname)s
    and devicetokens.id=%(tokid)s
    and not devicetokens.inactive
    and devicetokens.expires>current_timestamp"""

    sess_insert = """
insert into sessions (id, userid, ipaddress, devtok_id, refreshed)
values (%(sid)s, %(uid)s, %(ip)s, %(tokid)s, current_timestamp);"""

    results = api.Results()
    with app.dbconn() as conn:
        tokid = None
        if password:
            secret = password
            row = api.sql_1object(conn, select_user, {"uname": username.upper()})
        elif device_token:
            tokid, secret = decode_device_token(device_token)
            row = api.sql_1object(
                conn, select_devtok, {"uname": username.upper(), "tokid": tokid}
            )

        msg = None

        if device_token and row is None:
            msg = "unknown-token or mismatched-user"
        elif row is None:
            msg = "unknown-user"
        elif row.inactive:
            msg = "inactive-user"
        elif not row.comphash:
            msg = "no-password-configured"
        elif bcrypt.hashpw(
            secret.encode("utf8"), row.comphash.encode("utf8")
        ) != row.comphash.encode("utf8"):
            msg = "incorrect-password"
        elif device_token and row.expires < datetime.datetime.utcnow():
            msg = "expired-token"
        else:
            results.keys["status"] = f"welcome {row.username}"

        if msg:
            # show message in logs, but not to user
            print(f"Login failed for {username.upper()}:  {msg}")
            if device_token:
                body = "Unrecognized token or mis-matched user"
            else:
                body = "Unknown user or wrong password"
            raise api.UnauthorizedError("unknown-credentials", body)

        # generate and write session
        session = base64.b64encode(os.urandom(18)).decode("ascii")  # 24 characters
        assert len(session) == 24
        results.keys["session"] = session
        # TODO:  record the session expiration?
        params = {"sid": session, "uid": row.id, "ip": ip, "tokid": tokid}
        api.sql_void(conn, sess_insert, params)
        conn.commit()

        results.keys["access_token"] = yenotauth.core.session_token(session, row.id)
        results.keys["userid"] = row.id
        results.keys["username"] = row.username
        results.keys["capabilities"] = api.sql_tab2(conn, CAPS_SELECT, {"sid": session})

        # TODO set expiration to match token expiration
        # hmm, but then how to do the auto renewal?
        response.set_cookie(
            "YenotToken", results.keys["access_token"], httponly=True, path="/"
        )

    return results.json_out()


@app.post("/api/session-by-pin", name="api_session_by_pin", skip=["yenot-auth"])
def api_session_by_pin():
    username = request.forms.get("username")
    pin = request.forms.get("pin")
    ip = request.environ.get("REMOTE_ADDR")

    select = "select id, username, pinhash, target_2fa, inactive from users where username=%(user)s"
    sess_insert = """
insert into sessions (id, userid, ipaddress, refreshed, inactive, pin_2fa)
values (%(sid)s, %(uid)s, %(ip)s, %(to)s, true, %(pin6)s);"""

    results = api.Results()
    with app.dbconn() as conn:
        row = api.sql_1object(conn, select, {"user": username.upper()})

        msg = None

        if row == None:
            msg = "unknown-user"
        elif row.inactive:
            msg = "inactive-user"
        elif row.pinhash == None:
            msg = "no pin login for this user"
        elif bcrypt.hashpw(
            pin.encode("utf8"), row.pinhash.encode("utf8")
        ) != row.pinhash.encode("utf8"):
            msg = "incorrect-pin"
        else:
            results.keys["status"] = f"welcome {row.username}"

        if msg:
            # show message in logs, but not to user
            print(f"Login failed for {username.upper()}:  {msg}")
            body = "Unknown user or wrong password"
            raise api.UnauthorizedError("unknown-credentials", body)

        pin6 = [str(random.randint(0, 9)) for _ in range(6)]

        # generate and write session
        session = base64.b64encode(os.urandom(18)).decode("ascii")  # 24 characters
        assert len(session) == 24
        results.keys["session"] = session
        results.keys["access_token"] = yenotauth.core.session_token(
            session, row.id, duration=yenotauth.core.DURATION_2FA_TOKEN
        )
        params = {
            "sid": session,
            "uid": row.id,
            "ip": ip,
            "to": datetime.datetime.utcnow(),
            "pin6": "".join(pin6),
        }
        api.sql_void(conn, sess_insert, params)
        conn.commit()

        # TODO set expiration to match token expiration
        # hmm, but then how to do the auto renewal?
        response.set_cookie(
            "YenotToken", results.keys["access_token"], httponly=True, path="/"
        )

        t2fa = row.target_2fa
        if "file" in t2fa:
            import codecs

            dirname = os.environ["YENOT_2FA_DIR"]
            seg = codecs.encode(session.encode("ascii"), "hex").decode("ascii")
            fname = os.path.join(dirname, f"authpin-{seg}")
            with open(fname, "w") as f:
                f.write("".join(pin6))
        if "sms" in t2fa:
            from twilio.rest import Client

            # put your own credentials here

            account_sid = app.config["twilio"].account_sid
            auth_token = app.config["twilio"].auth_token
            src_phone = app.config["twilio"].src_phone

            pin6s = f"{''.join(pin6[:3])} {''.join(pin6[3:])}"
            client = Client(account_sid, auth_token)
            client.messages.create(
                to=t2fa["sms"],
                from_=src_phone,
                body=f"Your one-time PIN is {pin6s}",
            )

    return results.json_out()


@app.post(
    "/api/session/promote-2fa", name="api_session_promote_2fa", skip=["yenot-auth"]
)
def api_session_promote_2fa():
    session = yenotauth.core.request_session_id()
    pin2 = request.forms.get("pin2")

    ip = request.environ.get("REMOTE_ADDR")

    select = "select * from sessions where id=%(sid)s"
    sess_insert = """
insert into sessions (id, userid, ipaddress, refreshed)
values (%(sid)s, %(uid)s, %(ip)s, %(to)s);"""

    results = api.Results()
    with app.dbconn() as conn:
        sessrow = api.sql_1object(conn, select, {"sid": session})

        if sessrow == None or sessrow.pin_2fa != pin2:
            raise api.UnauthorizedError(
                "unknown-credentials", "Unknown session or mis-matched PIN"
            )

        # generate and write session
        session = base64.b64encode(os.urandom(18)).decode("ascii")  # 24 characters
        assert len(session) == 24
        results.keys["session"] = session
        results.keys["access_token"] = yenotauth.core.session_token(session, sessrow.id)
        sess_params = {
            "sid": session,
            "uid": sessrow.userid,
            "ip": ip,
            "to": datetime.datetime.utcnow(),
        }
        api.sql_void(conn, sess_insert, sess_params)
        conn.commit()

        results.keys["capabilities"] = api.sql_tab2(conn, CAPS_SELECT, {"sid": session})

        results.keys["username"] = api.sql_1row(
            conn,
            "select username from users join sessions on sessions.userid=users.id where sessions.id=%(sid)s",
            {"sid": session},
        )

        # TODO set expiration to match token expiration
        # hmm, but then how to do the auto renewal?
        response.set_cookie(
            "YenotToken", results.keys["access_token"], httponly=True, path="/"
        )

    return results.json_out()


@app.put("/api/session/logout", name="api_session_logout")
def api_session_logout():
    session = yenotauth.core.request_session_id()

    update = """
update sessions set inactive=true where id=%(sid)s"""

    with app.dbconn() as conn:
        api.sql_void(conn, update, {"sid": session})
        conn.commit()
    return api.Results().json_out()


def encode_device_token(tokid, secret):
    return f"ydt{tokid}xx{secret}"


def decode_device_token(devtoken):
    if not devtoken.startswith("ydt"):
        raise ValueError("a device token must have prefix 'ydt'.")
    tokid, secret = devtoken[3:].split("xx")
    return tokid, secret


@app.post("/api/user/<userid>/device-token/new", name="post_api_user_device_token_new")
def post_api_user_device_token_new(userid):
    device_name = request.params.get("device_name", None)
    expdays = int(
        request.params.get("expdays", yenotauth.core.DURATION_DEVICE_TOKEN_DAYS)
    )

    insert = """
insert into devicetokens (id, userid, device_name, tokenhash, issued, expires)
values (
    %(id)s, %(uid)s, %(dn)s,
    %(tokhash)s,
    current_timestamp, current_timestamp+(interval '1 day')*%(exp)s)
"""

    select = """
select id, userid, device_name, issued, expires, null::text as token
from devicetokens
where id=%(dtid)s"""

    dtid = "".join([f"{random.randrange(0, 2**16):04x}" for _ in range(8)])
    secret = "".join([f"{random.randrange(0, 2**16):04x}" for _ in range(8)])
    hashed = bcrypt.hashpw(secret.encode("utf8"), bcrypt.gensalt())
    hashed = hashed.decode("ascii")

    params = {
        "id": dtid,
        "uid": userid,
        "dn": device_name,
        "tokhash": hashed,
        "exp": expdays,
    }

    results = api.Results()
    with app.dbconn() as conn:
        api.sql_void(conn, insert, params)
        conn.commit()

        columns, rows = api.sql_tab2(conn, select, {"dtid": dtid})

        def xform_token(oldrow, row):
            row.token = encode_device_token(dtid, secret)

        rows = api.tab2_rows_transform((columns, rows), columns, xform_token)
        results.tables["device_token", True] = columns, rows
    return results.json_out()


@app.delete(
    "/api/user/<userid>/device-token/<devid>", name="delete_api_user_device_token"
)
def delete_api_user_device_token(userid, devid):
    delete = """
update devicetokens set inactive=true
where userid=%(userid)s and id=%(devid)s;
update sessions set inactive=true
where devtok_id=%(devid)s;"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"userid": userid, "devid": devid})
        conn.commit()
    return api.Results().json_out()


@app.get(
    "/api/sessions/active",
    name="get_api_sessions_active",
    report_title="Active Sessions",
)
def get_api_sessions_active():
    select = """
select users.id, users.username, sessions.ipaddress, sessions.refreshed,
    devicetokens.device_name
from sessions
join users on users.id=sessions.userid
left outer join devicetokens on devicetokens.id=sessions.devtok_id
where not sessions.inactive and sessions.refreshed>current_timestamp-interval '61 minutes'
"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(url_key="id"),
            ipaddress=api.cgen.auto(label="IP Address"),
        )
        results.tables["sessions", True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()


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
def get_users():
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
        string_agg(roles.role_name, '; ' order by role_name) as rolenames
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
select users.id, users.username, lastlog.ipaddress, lastlog.refreshed, active.count as active_count
from users
join lateral (
    select sessions.ipaddress, sessions.refreshed
    from sessions
    where sessions.userid=users.id
    order by refreshed desc
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


def get_activities_by_role_prompts():
    return []


@app.get(
    "/api/activities/by-role",
    name="api_activities_by_role",
    hide_report=True,
    report_title="Activities for Role",
    report_prompts=get_activities_by_role_prompts,
)
def get_activities_by_role():
    role_id = request.query.get("role", None)

    select = """
select activities.id, activities.description, activities.act_name, activities.url
from roles
join roleactivities on roleactivities.roleid=roles.id
join activities on activities.id=roleactivities.activityid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
            url=api.cgen.auto(label="URL"),
        )

        results.tables["activities", True] = api.sql_tab2(
            conn, select, {"r": role_id}, cm
        )

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += f"Activities for Role {rn}"

    return results.json_out()


def get_users_by_role_prompts():
    return []


@app.get(
    "/api/users/by-role",
    name="api_users_by_role",
    hide_report=True,
    report_title="Users for Role",
    report_prompts=get_users_by_role_prompts,
)
def get_users_by_role():
    role_id = request.query.get("role", None)

    select = """
select users.id, users.username, users.full_name, users.inactive
from roles
join userroles on userroles.roleid=roles.id
join users on users.id=userroles.userid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(
                label="Login Name", url_key="id", represents=True
            ),
        )

        results.tables["users", True] = api.sql_tab2(conn, select, {"r": role_id}, cm)

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += f"Users for Role {rn}"

    return results.json_out()


@app.get(
    "/api/roles/list",
    name="get_api_roles_list",
    report_title="Role List",
    report_sidebars=role_sidebar("id"),
)
def get_api_roles_list():
    select = """
select roles.id, roles.role_name, userroles2.count
from roles
left outer join (
                    select roleid, count(*)
                    from userroles 
                    join users on users.id=userroles.userid
                    group by roleid) as userroles2 on userroles2.roleid=roles.id
--order by roles.sort
"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
            count=api.cgen.auto(label="Users", skip_write=True),
        )
        results.tables["roles", True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()


@app.get("/api/role/new", name="get_api_role_new")
def get_api_role_new():
    select = """
select roles.id, roles.role_name, roles.sort
from roles
where false
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
        )
        cols, rows = api.sql_tab2(conn, select, None, cm)

        def default_row(index, row):
            row.id = str(uuid.uuid1())

        rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["role", True] = cols, rows
    return results.json_out()


@app.get("/api/role/<roleid>", name="get_api_role_record")
def get_api_role_record(roleid):
    select = """
select roles.id, roles.role_name, roles.sort
from roles
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
        )

        results.tables["role", True] = api.sql_tab2(conn, select, {"r": roleid}, cm)
    return results.json_out()


@app.put("/api/role/<roleid>", name="put_api_role_record")
def put_api_role_record(roleid):
    role = api.table_from_tab2(
        "role", amendments=["id"], required=["role_name", "sort"]
    )

    if len(role.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one role required.")

    for row in role.rows:
        if not hasattr(row, "id"):
            row.id = roleid

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows("roles", role)
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/role/<roleid>", name="delete_api_role_record")
def delete_api_role_record(roleid):
    # consider using cascade
    delete = """
delete from roleactivities where roleid=%(r)s;
delete from userroles where roleid=%(r)s;
delete from roles where id=%(r)s;
"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"r": roleid})
        conn.commit()
    return api.Results().json_out()


@app.get(
    "/api/activities/list",
    name="get_api_activities_list",
    report_title="Activity List",
    report_sidebars=activity_sidebar("id", "act_name"),
)
def get_api_activities_list():
    select = """
select activities.id, activities.act_name, activities.description, activities.url
from activities
"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity Name", url_key="id", represents=True
            ),
            url=api.cgen.auto(label="URL"),
        )

        rawdata = api.sql_tab2(conn, select, None, cm)

        from . import endpoints

        xform = endpoints.ReportMetaXformer(None)
        columns = api.tab2_columns_transform(
            rawdata[0], insert=[("url", "method", "title", "prompts", "sidebars")]
        )

        def xform_rptmeta(oldrow, row):
            if row.act_name in xform.routes:
                row.method = xform.routes[row.act_name].method
                if "report_title" in xform.routes[row.act_name].config:
                    row.title = xform.routes[row.act_name].config["report_title"]

            xform.xform(oldrow, row)

        rows = api.tab2_rows_transform(rawdata, columns, xform_rptmeta)

        results.tables["activities", True] = columns, rows
    return results.json_out()


@app.post("/api/activities", name="post_api_activities")
def post_api_activities():
    activities = api.table_from_tab2(
        "activities",
        amendments=["id"],
        required=["act_name", "description"],
        allow_extra=True,
    )

    for row in activities.rows:
        if not hasattr(row, "id"):
            row.id = uuid.uuid1().hex

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows("activities", activities)
        conn.commit()
    return api.Results().json_out()


@app.get("/api/activity/<activityid>", name="get_api_activity_record")
def get_api_activity_record(activityid):
    select = """
select activities.id, activities.act_name, activities.description, activities.note
from activities
where activities.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
        )

        results.tables["activity", True] = api.sql_tab2(
            conn, select, {"r": activityid}, cm
        )
    return results.json_out()


@app.delete("/api/activity/<activityid>", name="delete_api_activity_record")
def delete_api_activity_record(activityid):
    delete = """
delete from roleactivities where activityid=%(r)s;
delete from activities where id=%(r)s;
"""

    results = api.Results()
    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"r": activityid})
        conn.commit()
    return results.json_out()


@app.get("/api/userroles/by-users", name="get_api_userroles_by_users")
def get_api_userroles_by_users():
    # comma delimited list of user ids
    users = request.params.get("users").split(",")
    users = list(users)

    select = """
with users_universe as (
    select unnest(%(users)s)::uuid as userid
)
select roles.id, roles.role_name, u2.user_list
from roles
left outer join (
    select roleid, array_agg(userroles.userid::text) as user_list
    from userroles 
    join users_universe on users_universe.userid=userroles.userid
    group by roleid) as u2 on u2.roleid=roles.id
order by roles.sort
"""

    select2 = """
with users_universe as (
    select unnest(%(users)s)::uuid as userid
)
select users.id, users.username
from users 
where users.id in (select userid from users_universe)"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(url_key="id", represents=True),
        )

        p = {"users": users}
        results.tables["users", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["usernames"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/userroles/by-users", name="put_api_userroles_by_users")
def put_userroles_by_users():
    # Table userroles:
    # - id: roleid
    # - user_list: list of user id's to associate with this role
    coll = api.table_from_tab2("userroles", required=["id", "user_list"])
    # comma delimited list of user ids
    users = request.params.get("users").split(",")
    users = list(users)

    insert = """
-- insert role--user links for all users in universe not yet linked to role.
with users_add as (
    select * from (select unnest(%(users)s::uuid[]) as userid) as f
    where f.userid = any(%(tolink)s::uuid[])
), toinsert as (
    select %(id)s::uuid, users_add.userid
    from users_add
    left outer join userroles on userroles.roleid=%(id)s and userroles.userid=users_add.userid
    where userroles.userid is null
)
insert into userroles (roleid, userid)
(select * from toinsert)"""

    delete = """
-- insert role--user links for all users in universe not yet linked to role.
with users_del as (
    select * from (select unnest(%(users)s::uuid[]) as userid) as f
    where f.userid <> all(%(tolink)s::uuid[])
)
delete from userroles where userroles.roleid=%(id)s and 
                            userroles.userid in (select userid from users_del)"""

    with app.dbconn() as conn:
        for row in coll.rows:
            params = {"users": users, "tolink": list(row.user_list), "id": row.id}

            api.sql_void(conn, insert, params)
            api.sql_void(conn, delete, params)
        conn.commit()

    return api.Results().json_out()


@app.get("/api/userroles/by-roles", name="get_api_userroles_by_roles")
def get_api_userroles_by_roles():
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    select = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select users.id, users.username, u2.role_list
from users
left outer join (
    select userid, array_agg(userroles.roleid::text) as role_list
    from userroles 
    join roles_universe on roles_universe.roleid=userroles.roleid
    group by userid) as u2 on u2.userid=users.id
where not users.inactive
order by users.username
"""

    select2 = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select roles.id, roles.role_name
from roles
where roles.id in (select roleid from roles_universe)"""

    results = api.Results()
    results.key_labels += "Users for Role(s)"
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(url_key="id", represents=True),
        )

        p = {"roles": roles}
        results.tables["users", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["rolenames"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/userroles/by-roles", name="put_api_userroles_by_roles")
def put_api_userroles_by_roles():
    # Table userroles:
    # - id: user-id
    # - role_list: list of role-ids
    coll = api.table_from_tab2("userroles", required=["id", "role_list"])
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    insert = """
-- insert role--user links for all roles in universe not yet linked to role.
with roles_add as (
    select f.roleid from (select unnest(%(roles)s::uuid[]) as roleid) as f
    where f.roleid = any(%(tolink)s::uuid[])
), toinsert as (
    select %(id)s::uuid, roles_add.roleid
    from roles_add
    left outer join userroles on userroles.userid=%(id)s and userroles.roleid=roles_add.roleid
    where userroles.roleid is null
)
insert into userroles (userid, roleid)
(select * from toinsert)"""

    delete = """
-- insert role--user links for all roles in universe not yet linked to role.
with roles_del as (
    select * from (select unnest(%(roles)s::uuid[]) as roleid) as f
    where f.roleid <> all(%(tolink)s::uuid[])
)
delete from userroles where userroles.userid=%(id)s::uuid and 
                            userroles.roleid in (select roleid from roles_del)"""

    with app.dbconn() as conn:
        for row in coll.rows:
            params = {"roles": roles, "tolink": list(row.role_list), "id": row.id}

            api.sql_void(conn, insert, params)
            api.sql_void(conn, delete, params)
        conn.commit()

    return api.Results().json_out()


@app.get("/api/roleactivities/by-roles", name="get_api_roleactivities_by_roles")
def get_api_roleactivities_by_roles():
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    select = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select activities.id, activities.act_name, activities.description, 
        (
            select array_to_json(array_agg(row_to_json(d)))
            from (
                select ra.roleid, ra.permitted, ra.dashboard, ra.dashprompts
                from roleactivities as ra
                join roles_universe on roles_universe.roleid=ra.roleid
                where ra.activityid=activities.id
            ) as d
        ) as permissions
from activities;
"""

    select2 = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select roles.id, roles.role_name, roles.sort
from roles join roles_universe on roles_universe.roleid=roles.id"""

    results = api.Results()
    results.key_labels += "Activities for Role(s)"
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
        )

        p = {"roles": roles}
        results.tables["activities", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["rolenames"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/roleactivities/by-roles", name="put_api_roleactivities_by_roles")
def put_api_roleactivities_by_roles():
    # Table roleactivities:
    # - id: activityid
    # - permissions: list of dictionaries with key roleid and associated metadata
    coll = api.table_from_tab2("roleactivities", required=["id", "permissions"])
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    update = """
-- update activity--role links for all roles in universe linked with some prior values.
with /*PERMISSIONS*/
, toupdate as (
    select permissions.*
    from permissions
    join roleactivities on 
        roleactivities.activityid=%(id)s and roleactivities.roleid=permissions.roleid
)
update roleactivities set
    permitted=toupdate.permitted,
    dashboard=toupdate.dashboard,
    dashprompts=toupdate.dashprompts
from toupdate
where toupdate.roleid=roleactivities.roleid and roleactivities.activityid=%(id)s"""

    insert = """
-- insert activity--role links for all roles in universe not yet linked to activity.
with /*PERMISSIONS*/
, toinsert as (
    select %(id)s::uuid as activityid, permissions.*
    from permissions
    left outer join roleactivities on 
        roleactivities.activityid=%(id)s and roleactivities.roleid=permissions.roleid
    where roleactivities.roleid is null
)
insert into roleactivities (activityid, roleid, permitted, dashboard, dashprompts)
(select * from toinsert)"""

    delete = """
-- insert role--role links for all roles in universe not yet linked to role.
with roles_del as (
    select * from (select unnest(%(roles)s)::uuid as roleid) as f
    where f.roleid not in %(tolink)s
)
delete from roleactivities where roleactivities.activityid=%(id)s and 
                            roleactivities.roleid in (select roleid from roles_del)"""

    with app.dbconn() as conn:
        # TODO:  use upsert
        api.sql_void(conn, "set transaction isolation level serializable")

        for row in coll.rows:
            represented = [r["roleid"] for r in row.permissions]

            columns = ["roleid", "permitted", "dashboard", "dashprompts"]
            permlist = api.InboundTable([(c, None) for c in columns], [])
            for passed in row.permissions:
                if passed["roleid"] not in roles:
                    raise RuntimeError(
                        "roles parameter establishes universe of allowed values"
                    )
                permlist.rows.append(
                    permlist.DataRow(
                        passed["roleid"],
                        passed.get("permitted", False),
                        passed.get("dashboard", False),
                        passed.get("dashprompts", None),
                    )
                )

            # TODO: fix the ugly requirement for something to be in tolink param of delete:
            params = {
                "roles": roles,
                "tolink": tuple(represented)
                if len(represented) > 0
                else ("__bug_happens_here__",),
                "id": row.id,
            }

            # delete
            api.sql_void(conn, delete, params)
            if len(represented) > 0:
                ctypes = ["uuid", "boolean", "boolean", "json"]
                mogrifications = permlist.as_cte(
                    conn, "permissions", column_types=ctypes
                )

                # update
                my_update = update.replace("/*PERMISSIONS*/", mogrifications)
                api.sql_void(conn, my_update, params)
                # insert
                my_insert = insert.replace("/*PERMISSIONS*/", mogrifications)
                api.sql_void(conn, my_insert, params)

        conn.commit()

    return api.Results().json_out()
