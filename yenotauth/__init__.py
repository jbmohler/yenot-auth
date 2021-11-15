import os
import getpass
import yenot.backend.api as api
from . import core


def yenot_auth_app_init(app):
    app.__class__.raise_unauthorized = core.raise_unauthorized
    app.__class__.endpoints = core.endpoints
    app.__class__.report_endpoints = core.report_endpoints
    app.__class__.request_content_title = core.request_content_title
    app.install(core.YenotAuth())

    api.active_user = core.active_user
    app.request_user_id = core.request_user_id
    app.request_session_id = core.request_session_id


def yenot_auth_data_init(conn, args):
    from . import initdb

    initdb.load_essentials(conn)
    if args.user != None:
        if os.environ.get("INIT_DB_PASSWORD", None) != None:
            pw = os.environ["INIT_DB_PASSWORD"]
        else:
            pw = getpass.getpass("Password for {}: ".format(args.user))
        initdb.create_yenot_user(conn, args.user, pw)


api.add_server_init(yenot_auth_app_init)
api.add_data_init(yenot_auth_data_init)
