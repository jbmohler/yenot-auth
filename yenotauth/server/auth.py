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

    assert userid or sessrow.userid

    # generate and write session
    if create_new_session:
        session_id = str(uuid.uuid4())
    else:
        session_id = sessrow.id
        if not userid:
            userid = sessrow.userid

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
        results.keys["access_expiration"] = expires
        results.tables["capabilities"] = api.sql_tab2(
            conn, CAPS_SELECT, {"sid": session_id}
        )

    if token_type == "2fa-verify":
        results.keys["2fa-prompt"] = True

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
where addresses.userid=%(uid)s and is_2fa_target and is_verified
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
        elif not bcrypt.checkpw(secret.encode("utf8"), row.comphash.encode("utf8")):
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
select id, refresh_hash, userid
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


@app.get("/api/session/check", name="api_session_check")
def api_session_check(request):
    session = yenotauth.core.request_session_id()

    results = api.Results()
    with app.dbconn() as conn:
        active = api.active_user(conn)

        results.keys["userid"] = active.id
        results.keys["username"] = active.username
        results.tables["capabilities"] = api.sql_tab2(
            conn, CAPS_SELECT, {"sid": session}
        )
        results.keys["access_expiration"] = active.expires.timestamp()

    return results.json_out()


@app.post("/api/session-by-pin", name="api_session_by_pin", skip=["yenot-auth"])
def api_session_by_pin(request):
    username = request.forms.get("username")
    pin = request.forms.get("pin")
    ip = request.environ.get("REMOTE_ADDR")

    select = "select id, username, pinhash, inactive from users where username=%(user)s"

    select2fa = """
select id, addr_type, address
from addresses
where addresses.userid=%(uid)s and is_2fa_target and is_verified
"""

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
        elif not bcrypt.checkpw(pin.encode("utf8"), row.pinhash.encode("utf8")):
            msg = "incorrect-pin"
        else:
            results.keys["status"] = f"welcome {row.username}"

        if msg:
            # show message in logs, but not to user
            print(f"Login failed for {username.upper()}:  {msg}")
            body = "Unknown user or wrong password"
            raise api.UnauthorizedError("unknown-credentials", body)

        addr_2fa = api.sql_rows(conn, select2fa, {"uid": row.id})
        req_2fa = len(addr_2fa) > 0
        if not req_2fa:
            # show message in logs, but not to user
            msg = "PIN matched, but 2FA required"
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

        for target in addr_2fa:
            messaging.communicate_2fa(target, session_id, pin6)

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
def put_api_user_send_invite(request, userid):
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
        target = api.sql_1object(conn, select, {"uid": userid})

        if not target:
            raise api.UserError(
                "unknown-record",
                "This user has no addresses configured to receive the invite.",
            )

        user = api.sql_1object(
            conn,
            "select username, full_name from users where id=%(uid)s",
            {"uid": userid},
        )

        session_id = generate_session_cookies(
            conn,
            results,
            create_new_session=True,
            invite_token=True,
            userid=userid,
        )

        conn.commit()

        token = results.keys["invite_token"]
        messaging.communicate_invite(target, userid, request, token, user)

        results.keys["destination"] = target.address

    return results.json_out()


@app.put(
    "/api/user/<userid>/accept-invite",
    name="put_api_user_accept_invite",
    skip=["yenot-auth"],
)
def put_api_user_accept_invite(request, userid):
    token = request.forms.get("token")
    if token is None:
        raise api.ForbiddenError(
            "unknown-token", "No authenticated session to refresh."
        )
    claims = yenotauth.core.verify_jwt_exception(token, "invite")

    password = request.forms.get("password")

    select_session = """
select sessions.id, users.id as userid, users.username, sessions.expires
from sessions
join users on users.id=sessions.userid
where sessions.id=%(sid)s
"""

    update = """
update users set pwhash=%(h)s where id=%(i)s"""

    with app.dbconn() as conn:
        session = api.sql_1object(
            conn, select_session, {"sid": claims["yenot-session-id"]}
        )

        if not session:
            raise api.ForbiddenError(
                "unknown-token",
                "This invite token cannot be found.  Ask for a new invite from the system administrator.",
            )

        if userid != session.userid:
            raise api.ForbiddenError("unknown-token", "Token does not match this user.")

        hashed = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
        hashed = hashed.decode("ascii")

        api.sql_void(conn, update, {"h": hashed, "i": userid})
        api.sql_void(
            conn,
            "update sessions set inactive=false where id=%(sid)s",
            {"sid": claims["sub"]},
        )
        conn.commit()
    return api.Results().json_out()


def encode_device_token(tokid, secret):
    return f"ydt{tokid}xx{secret}"


def decode_device_token(devtoken):
    if not devtoken.startswith("ydt"):
        raise ValueError("a device token must have prefix 'ydt'.")
    tokid, secret = devtoken[3:].split("xx")
    return tokid, secret


@app.post("/api/user/me/device-token/new", name="post_api_user_me_device_token_new")
@app.post("/api/user/<userid>/device-token/new", name="post_api_user_device_token_new")
def post_api_user_device_token_new(request, userid=None):
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

    with app.dbconn() as conn:
        active = api.active_user(conn)
        userid = active.id

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
