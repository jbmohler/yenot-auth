import os
import time
import jose.jwt
import rtlib
from bottle import HTTPError, request
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


def session_token(session, user_id):
    token_claims = {
        "iss": "yenot-auth",
        "sid": session,
        "sub": user_id,
        "iat": time.time(),
        "exp": time.time() + 60 * 60 * 24,  # 24 hours
    }

    secret = os.environ["YENOT_AUTH_SIGNING_SECRET"]
    return jose.jwt.encode(token_claims, secret, algorithm="HS256")


def request_session_id():
    sid = None

    if "Authorization" in request.headers:
        bearer = request.headers["Authorization"]
        if bearer.startswith("Bearer "):
            token = bearer[7:].strip()

            claims = jose.jwt.decode(
                token, os.environ["YENOT_AUTH_SIGNING_SECRET"], algorithms=["HS256"]
            )
            sid = claims["sid"]

    if sid == None:
        sid = request.headers.get("X-Yenot-SessionID", None)

    return sid


def request_user_id(conn):
    if "Authorization" in request.headers:
        bearer = request.headers["Authorization"]
        if bearer.startswith("Bearer "):
            token = bearer[7:].strip()

            claims = jose.jwt.decode(
                token, os.environ["YENOT_AUTH_SIGNING_SECRET"], algorithms=["HS256"]
            )
            return claims["sub"]

    if "X-Yenot-SessionID" in request.headers:
        sid = request.headers.get("X-Yenot-SessionID", None)

        select = """
select userid
from sessions
where sessions.id=%(sid)s
"""

        return api.sql_1row(conn, select, {"sid": sid})

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
            raise HTTPError(401, "no current session found")
        elif len([r for r in rows if r.role_name is not None]) == 0:
            raise HTTPError(403, "Content forbidden")
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
                raise HTTPError(401, "Content forbidden (provide valid bearer token)")
            rname = route.name
            self.checkauth(sid, rname)
            return callback(*args, **kwargs)

        return wrapper
