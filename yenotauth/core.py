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


def active_user(conn):
    select = """
select users.id, users.username
from sessions
join users on users.id=sessions.userid
where sessions.id=%(sid)s
"""
    sid = request.headers.get("X-Yenot-SessionID", None)
    return api.sql_1object(conn, select, {"sid": sid})


def request_content_title(self):
    title = request.route.config.get("_yenot_title_", None)
    if title in ("", None):
        title = request.route.config.get("report_title", None)
    if title in ("", None):
        title = request.route.name
    return title


AUTH_SELECT = """
select roles.role_name, activities.description
from sessions
join userroles on userroles.userid=sessions.userid
join roleactivities on roleactivities.roleid=userroles.roleid
join activities on activities.id=roleactivities.activityid
join roles on roles.id=userroles.roleid
where sessions.id=%(sid)s
    and not sessions.inactive
    and activities.act_name=%(act)s
    and roleactivities.permitted
"""


def raise_unauthorized(app, routename, sid=None):
    if sid == None:
        sid = request.headers.get("X-Yenot-SessionID", None)

    with app.dbconn() as conn:
        rows = api.sql_rows(conn, AUTH_SELECT, {"sid": sid, "act": routename})
        if len(rows) == 0:
            raise HTTPError(401, "Content forbidden")
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
            sid = request.headers.get("X-Yenot-SessionID", None)
            if sid == None:
                raise HTTPError(
                    401, "Content forbidden (X-Yenot-SessionID header required)"
                )
            rname = route.name
            self.checkauth(sid, rname)
            return callback(*args, **kwargs)

        return wrapper
