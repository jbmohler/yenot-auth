import os
import base64
import jose.jwt
import jose.exceptions
import rtlib
from bottle import request
import yenot.backend.api as api


def report_endpoints(app):
    return [
        r
        for r in app.routes
        if "report_title" in r.config and not r.config.get("hide_report", False)
    ]


def route_prompts(r):
    return [] if "report_prompts" not in r.config else r.config["report_prompts"]()


def route_sidebars(r):
    return [] if "report_sidebars" not in r.config else r.config["report_sidebars"]


def endpoints(self):
    kls_endpoint = rtlib.fixedrecord("Endpoint", ["method", "url", "name", "config"])
    destinations = [r for r in self.routes]
    return [
        kls_endpoint(r.method, r.rule[1:], r.name, r.config)
        for r in destinations
        if r.rule[1:] != ""
    ]


# access and refresh tokens have the same duration but different audiences
DURATION_ACCESS_TOKEN = 60 * 60  # 1 hour
DURATION_INVITE = 24 * 60 * 60  # 1 day
DURATION_2FA_TOKEN = 5 * 60  # 5 minutes
DURATION_DEVICE_TOKEN_DAYS = 30


def generate_pin6():
    # a 6 digit pin has just under 20 bits of randomness, 3
    # bytes has 24
    gen1 = os.urandom(3)
    gen2 = [256 ** i * b for i, b in enumerate(gen1)]
    gen3 = gen2[0] * gen2[1] * gen2[2]
    return f"{gen3:06}"[-6:]


def generate_crypt_id24():
    g = base64.b64encode(os.urandom(18)).decode("ascii")  # 24 characters
    assert len(g) == 24
    return g


def session_token(userid, issued, expires, claims):
    token_claims = {
        "iss": "yenot-auth",
        "sub": str(userid),
        "iat": issued,
        "exp": expires,
        **claims,
    }

    secret = os.environ["YENOT_AUTH_SIGNING_SECRET"]
    return jose.jwt.encode(token_claims, secret, algorithm="HS256")


def request_token():
    token = None

    # TODO: not going to support this any more
    if "Authorization" in request.headers:
        bearer = request.headers["Authorization"]
        if bearer.startswith("Bearer "):
            token = bearer[7:].strip()

    if "YenotToken" in request.cookies:
        token = request.cookies.get("YenotToken")

    return token


def verify_jwt_exception(token, audience):
    try:
        claims = jose.jwt.decode(
            token, os.environ["YENOT_AUTH_SIGNING_SECRET"], algorithms=["HS256"]
        )
    except jose.exceptions.ExpiredSignatureError:
        raise api.ForbiddenError(
            "expired-token", "Access token is unrecognized or expired."
        )

    if claims["yenot-type"] != audience:
        raise api.ForbiddenError(
            "incorrect-token", "Token is used in the wrong context."
        )

    return claims


def request_session_id():
    sid = None

    token = request_token()

    if token:
        sid = verify_jwt_exception(token, "access")["yenot-session-id"]

    return sid


def request_user_id(conn):
    # TODO remove
    raise NotImplementedError()
    token = request_token()

    if token:
        return verify_jwt_exception(token, "access")["sub"]

    return None


def active_user(conn):
    select = """
select users.id, users.username
from sessions
join users on users.id=sessions.userid
where sessions.id=%(sid)s
"""

    return api.sql_1object(conn, select, {"sid": request_session_id()})


def request_content_title(self):
    title = request.route.config.get("_yenot_title_", None)
    if title in ("", None):
        title = request.route.config.get("report_title", None)
    if title in ("", None):
        title = request.route.name
    return title


AUTH_SELECT = """
select sessions.userid, sessions.inactive,
    sessions.expires<current_timestamp as expired,
    activity.role_name, activity.description
from sessions
left outer join lateral (
    select roles.role_name, activities.description
    from userroles
    join roleactivities on roleactivities.roleid=userroles.roleid
    join activities on activities.id=roleactivities.activityid
    join roles on roles.id=userroles.roleid
    where userroles.userid=sessions.userid
        and activities.act_name=%(act)s
        and roleactivities.permitted
    ) activity on true
where sessions.id=%(sid)s
    and not sessions.inactive
"""


def raise_unauthorized(app, routename, sid=None):
    if sid == None:
        sid = request_session_id()

    with app.dbconn() as conn:
        rows = api.sql_rows(conn, AUTH_SELECT, {"sid": sid, "act": routename})
        if len(rows) == 0:
            raise api.UnauthorizedError("unknown-session", "no current session found")
        elif len([r for r in rows if r.role_name is not None]) == 0:
            raise api.ForbiddenError("user-unauthorized", "Content forbidden")
        elif rows[0].expired:
            raise api.ForbiddenError(
                "expired-token", "Access token is unrecognized or expired."
            )
        else:
            request.route.config["_yenot_title_"] = rows[0].description
    return True


class YenotAuth:
    name = "yenot-auth"
    api = 2

    def setup(self, app):
        # expect app to have dbconn
        self.app = app

    def checkauth(self, sid, routename):
        self.app.raise_unauthorized(routename, sid=sid)

    def apply(self, callback, route):
        def wrapper(*args, **kwargs):
            sid = request_session_id()
            if sid == None:
                raise api.UnauthorizedError(
                    "no-session", "Content forbidden (provide valid bearer token)"
                )
            rname = route.name
            self.checkauth(sid, rname)
            return callback(*args, **kwargs)

        return wrapper
