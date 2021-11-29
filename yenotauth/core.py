import os
import time
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


DURATION_ACCESS_TOKEN = 60 * 60  # 1 hour
DURATION_2FA_TOKEN = 5 * 60  # 5 minutes
DURATION_DEVICE_TOKEN_DAYS = 30


def session_token(session, user_id, duration=None):
    if duration is None:
        duration = DURATION_ACCESS_TOKEN
    token_claims = {
        "iss": "yenot-auth",
        "sid": session,
        "sub": user_id,
        "iat": time.time(),
        "exp": time.time() + duration,
    }

    secret = os.environ["YENOT_AUTH_SIGNING_SECRET"]
    return jose.jwt.encode(token_claims, secret, algorithm="HS256")


def request_token():
    token = None

    if "Authorization" in request.headers:
        bearer = request.headers["Authorization"]
        if bearer.startswith("Bearer "):
            token = bearer[7:].strip()

    if "YenotToken" in request.cookies:
        token = request.cookies.get("YenotToken")

    return token


def request_session_id():
    sid = None

    token = request_token()

    if token:
        try:
            claims = jose.jwt.decode(
                token, os.environ["YENOT_AUTH_SIGNING_SECRET"], algorithms=["HS256"]
            )
        except jose.exceptions.ExpiredSignatureError:
            raise api.ForbiddenError(
                "expired-token", "Access token is unrecognized or expired."
            )
        sid = claims["sid"]

    return sid


def request_user_id(conn):
    token = request_token()

    if token:
        try:
            claims = jose.jwt.decode(
                token, os.environ["YENOT_AUTH_SIGNING_SECRET"], algorithms=["HS256"]
            )
        except jose.exceptions.ExpiredSignatureError:
            raise api.ForbiddenError(
                "expired-token", "Access token is unrecognized or expired."
            )
        return claims["sub"]

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
    sessions.refreshed<current_timestamp-interval '60 minutes' as expired,
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
