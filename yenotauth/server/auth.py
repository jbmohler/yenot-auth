import uuid
import time
import datetime
import random
import bcrypt
import yenot.backend.api as api
import yenotauth.core
from . import messaging

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


def role_sidebar(idcolumn):
    return [{"name": "role_general", "on_highlight_row": {"id": idcolumn}}]


def activity_sidebar(idcolumn, namecolumn):
    return [
        {
            "name": "activity_general",
            "on_highlight_row": {"id": idcolumn, "act_name": namecolumn},
        }
    ]


def generate_session_cookies(
    conn,
    results,
    *,
    create_new_session=False,
    new_session_2fa=False,
    invite_token=False,
    sessrow=None,
    userid=None,
    devtok_id=None,
    ipaddress=None,
    pin_2fa=None,
):
    # xor :)
    assert create_new_session or sessrow
    assert not create_new_session or not sessrow

    # generate and write session
    if create_new_session:
        session_id = uuid.uuid4().hex
    else:
        session_id = str(sessrow.id)

    if new_session_2fa:
        refresh_pwd = None
        hashed = None
    else:
        refresh_pwd = yenotauth.core.generate_crypt_id24()

        hashed = bcrypt.hashpw(refresh_pwd.encode("utf8"), bcrypt.gensalt())
        hashed = hashed.decode("ascii")

    token_type = None
    if new_session_2fa:
        token_type = "2fa-verify"
    elif invite_token:
        token_type = "invite"
    else:
        token_type = "access"

    duration = {
        "2fa-verify": yenotauth.core.DURATION_2FA_TOKEN,
        "invite": yenotauth.core.DURATION_INVITE,
        "access": yenotauth.core.DURATION_ACCESS_TOKEN,
    }[token_type]

    issued = time.time()
    expires = issued + duration

    sess_insert = """
insert into sessions (id, refresh_hash, userid, ipaddress, devtok_id, issued, expires, pin_2fa)
values (%(sid)s, %(refhash)s, %(uid)s, %(ip)s, %(tokid)s,
            timestamp 'epoch' + %(iss)s * interval '1 second',
            timestamp 'epoch' + %(exp)s * interval '1 second',
            %(p2fa)s);"""

    # Updates refresh_id & expires effectively performing refresh token rotation
    sess_update = """
update sessions set 
    refresh_hash=%(rid)s,
    expires=timestamp 'epoch' + %(exp)s * interval '1 second'
where sessions.id=%(sid)s and not sessions.inactive
returning sessions.id, sessions.refresh_hash, sessions.userid
"""

    if create_new_session:
        # TODO: only save pin_2fa as a bcrypt hash
        params = {
            "sid": session_id,
            "refhash": hashed,
            "uid": userid,
            "ip": ipaddress,
            "tokid": devtok_id,
            "iss": issued,
            "exp": expires,
            "p2fa": pin_2fa,
        }
        api.sql_void(conn, sess_insert, params)
    else:
        params = {"sid": session_id, "rid": hashed, "exp": expires}
        api.sql_void(conn, sess_update, params)

    if not invite_token:
        access_token = yenotauth.core.session_token(
            userid,
            issued,
            expires,
            {"yenot-session-id": session_id, "yenot-type": token_type},
        )
    else:
        access_token = yenotauth.core.session_token(
            userid,
            issued,
            expires,
            {
                "yenot-session-id": session_id,
                "yenot-refresh-id": refresh_pwd,
                "yenot-type": token_type,
            },
        )
    if token_type == "access":
        refresh_token = yenotauth.core.session_token(
            userid,
            issued,
            expires,
            {
                "yenot-session-id": session_id,
                "yenot-refresh-id": refresh_pwd,
                "yenot-type": "refresh",
            },
        )

    # Refresh & access tokens go only as httponly cookies.  They are never
    # returned in the payload.
    if token_type == "invite":
        results.keys["invite_token"] = access_token
    if token_type == "access":
        results.keys["userid"] = userid
        results.keys["username"] = api.sql_1row(
            conn,
            "select username from users where id=%(uid)s",
            {"uid": userid},
        )
        results.keys["capabilities"] = api.sql_tab2(
            conn, CAPS_SELECT, {"sid": session_id}
        )

    if token_type != "invite":
        results.set_cookie("YenotToken", access_token, httponly=True, path="/")
        if not new_session_2fa:
            results.set_cookie(
                "YenotRefreshToken", refresh_token, httponly=True, path="/api/session"
            )

    return session_id


@app.post("/api/session", name="api_session", skip=["yenot-auth"])
def api_session(request):
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

    select2fa = """
select id, addr_type, address
from addresses
where addresses.userid=%(uid)s and is_2fa_target
"""

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

        addr_2fa = api.sql_rows(conn, select2fa, {"uid": row.id})
        req_2fa = len(addr_2fa) > 0

        pin6 = yenotauth.core.generate_pin6() if req_2fa else None

        session_id = generate_session_cookies(
            conn,
            results,
            create_new_session=True,
            new_session_2fa=req_2fa,
            userid=row.id,
            devtok_id=tokid,
            ipaddress=ip,
            pin_2fa=pin6,
        )

        if req_2fa:
            for target in addr_2fa:
                messaging.communicate_2fa(target, session_id, pin6)

        conn.commit()

    return results.json_out()


@app.get("/api/session/refresh", name="api_session_refresh", skip=["yenot-auth"])
def api_session_refresh(request):
    # Require a refresh token and issue a new refresh token and access token.
    # Note that this end-point is effectively double auth-ed since it will
    # receive an access token cookie which is verified by the framework.
    token = request.cookies.get("YenotRefreshToken")
    if token is None:
        raise api.ForbiddenError(
            "unknown-token", "No authenticated session to refresh."
        )
    claims = yenotauth.core.verify_jwt_exception(token, "refresh")
    session_id = claims["yenot-session-id"]
    refresh_pwd = claims["yenot-refresh-id"]

    select = """
select id, refresh_hash
from sessions
where id=%(sid)s and not inactive
"""

    results = api.Results()
    with app.dbconn() as conn:
        # Note: this rotates the refresh_id but does not change the session_id
        # (part of the access token).  This seems counter-intuitive but it is a
        # secure implementation by virtue of the signing of the JWT which
        # includes an expiration.

        # get the session row & check refresh hash
        sessrow = api.sql_1object(conn, select, {"sid": session_id})

        if sessrow is None:
            # One possible way to get here is that the refresh token was
            # already used by a malicious actor.
            print("No session found")
            raise api.ForbiddenError("unknown-token", "Passed refresh token not found.")

        if bcrypt.hashpw(
            refresh_pwd.encode("utf8"), sessrow.refresh_hash.encode("utf8")
        ) != sessrow.refresh_hash.encode("utf8"):
            # One possible way to get here is that the refresh token was
            # already used by a malicious actor.
            print("refresh pwd did not match")
            raise api.ForbiddenError("unknown-token", "Passed refresh token not found.")

        generate_session_cookies(conn, results, sessrow=sessrow)
        conn.commit()

    return results.json_out()


@app.post("/api/session-by-pin", name="api_session_by_pin", skip=["yenot-auth"])
def api_session_by_pin(request):
    username = request.forms.get("username")
    pin = request.forms.get("pin")
    ip = request.environ.get("REMOTE_ADDR")

    select = "select id, username, pinhash, inactive from users where username=%(user)s"

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

        pin6 = yenotauth.core.generate_pin6()

        session_id = generate_session_cookies(
            conn,
            results,
            create_new_session=True,
            new_session_2fa=True,
            userid=row.id,
            ipaddress=ip,
            pin_2fa=pin6,
        )

        messaging.communicate_2fa(row.target_2fa, session_id, pin6)

        conn.commit()

    return results.json_out()


@app.post(
    "/api/session/promote-2fa", name="api_session_promote_2fa", skip=["yenot-auth"]
)
def api_session_promote_2fa(request):
    token = request.cookies.get("YenotToken")
    claims = yenotauth.core.verify_jwt_exception(token, "2fa-verify")
    session = claims["yenot-session-id"]
    pin2 = request.forms.get("pin2")

    ip = request.environ.get("REMOTE_ADDR")

    select = "select * from sessions where id=%(sid)s"

    results = api.Results()
    with app.dbconn() as conn:
        sessrow = api.sql_1object(conn, select, {"sid": session})

        # TODO:  should this pin_2fa be hashed?
        if sessrow == None or sessrow.pin_2fa != pin2:
            raise api.UnauthorizedError(
                "unknown-credentials", "Unknown session or mis-matched PIN"
            )

        # generate and write session
        generate_session_cookies(
            conn,
            results,
            create_new_session=True,
            userid=sessrow.userid,
            devtok_id=sessrow.devtok_id,
            ipaddress=ip,
        )
        conn.commit()

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


@app.put("/api/user/<userid>/send-invite", name="put_api_user_send_invite")
def put_api_user_send_invite(userid):
    # prefer primary or 2fa-targets
    select = """
select id, addr_type, address, is_2fa_target, is_primary
from addresses
where userid=%(uid)s
order by case when is_primary then 0 else 1 end, case when is_2fa_target then 0 else 1 end
limit 1
"""

    results = api.Results()
    with app.dbconn() as conn:
        target = api.sql_1row(conn, select, {"uid": userid})

        # TODO:  I feel like I should validate the user, but the appearance of an address does so?

        session_id = generate_session_cookies(
            conn,
            results,
            create_new_session=True,
            invite_token=True,
            userid=userid,
        )

        messaging.communicate_invite(target, session_id, token)

    return api.Results().json_out()


def encode_device_token(tokid, secret):
    return f"ydt{tokid}xx{secret}"


def decode_device_token(devtoken):
    if not devtoken.startswith("ydt"):
        raise ValueError("a device token must have prefix 'ydt'.")
    tokid, secret = devtoken[3:].split("xx")
    return tokid, secret


@app.post("/api/user/<userid>/device-token/new", name="post_api_user_device_token_new")
def post_api_user_device_token_new(request, userid):
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

    # TODO: use os.urandom
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


@app.delete("/api/user/me/device-token/<devid>", name="delete_api_user_me_device_token")
def delete_api_user_me_device_token(devid):
    with app.dbconn() as conn:
        active = api.active_user(conn)
        userid = active.id

    return delete_api_user_device_token(userid, devid)


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
select users.id, users.username, sessions.ipaddress, sessions.issued,
    devicetokens.device_name
from sessions
join users on users.id=sessions.userid
left outer join devicetokens on devicetokens.id=sessions.devtok_id
where not sessions.inactive and sessions.expires>current_timestamp
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


def get_activities_by_role_prompts():
    return []


@app.get(
    "/api/activities/by-role",
    name="api_activities_by_role",
    hide_report=True,
    report_title="Activities for Role",
    report_prompts=get_activities_by_role_prompts,
)
def get_activities_by_role(request):
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
def get_users_by_role(request):
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
def get_api_userroles_by_users(request):
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
def put_userroles_by_users(request):
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
def get_api_userroles_by_roles(request):
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
def put_api_userroles_by_roles(request):
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
def get_api_roleactivities_by_roles(request):
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
def put_api_roleactivities_by_roles(request):
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
