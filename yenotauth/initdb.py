import re
import bcrypt
import yenot.backend.api as api

SYS_ADMIN_ROLE = ("System Administrator", 999)
USER_ROLE = ("User", 1)

PUBLIC_ACTS = ["api_session", "api_session_by_pin", "api_session_promote_2fa"]

USER_ACTS = [
    "get_api_user_me_record",
    "put_api_user_me",
    "api_user_me_change_password",
    "api_user_me_change_pin",
    "get_api_user_me_address_new",
    "get_api_user_me_address",
    "put_api_user_me_address",
    "put_api_user_me_address_verify",
    "delete_api_user_me_address",
    "get_api_user_me_avatar",
    "post_api_user_me_device_token_new",
    "delete_api_user_me_device_token",
    "api_session_check",
    "api_session_logout",
    "api_user_reports",
]

SYS_ADMIN_ACTS = [
    "get_api_sessions_active",
    "get_api_users_list",
    "get_api_user_record",
    "api_endpoints",
    "api_users_lastlogin",
    "post_api_user_device_token_new",
    "delete_api_user_device_token",
    "get_api_user_address_new",
    "get_api_user_address",
    "put_api_user_address",
    "delete_api_user_address",
    "get_api_roles_list",
    "get_api_role_new",
    "get_api_role_record",
    "put_api_role_record",
    "delete_api_role_record",
    "get_api_activities_list",
    "post_api_activities",
    "get_api_activity_record",
    "delete_api_activity_record",
    "api_activities_by_role",
    "api_users_by_role",
    "put_api_user",
    "post_api_user",
    "put_api_user_send_invite",
    "get_api_userroles_by_users",
    "put_api_userroles_by_users",
    "get_api_userroles_by_roles",
    "put_api_userroles_by_roles",
    "get_api_roleactivities_by_roles",
    "put_api_roleactivities_by_roles",
]


def register_activities(conn):
    app = api.get_global_app()

    with conn.cursor() as cursor:
        ins = """
insert into activities (act_name, description, url)
values(%(n)s, %(d)s, %(u)s)
on conflict (act_name) do nothing"""
        for ep in app.endpoints():
            cursor.execute(
                ins,
                {
                    "n": ep.name,
                    "d": getattr(ep, "config", {}).get("report_title", None),
                    "u": ep.url,
                },
            )


def rolemap_activities(conn, routes, roles):
    select_unroled = """
select activities.*
from activities
join lateral (
    select count(*) 
    from roleactivities 
    where activityid=activities.id) mapcount on true
where mapcount.count=0
"""

    ins2 = """
insert into roleactivities (roleid, activityid)
values (
    (select id from roles where role_name=%(rn)s),
    (select id from activities where act_name=%(u)s))"""

    rows = api.sql_rows(conn, select_unroled)

    for row in rows:
        for route, role in zip(routes, roles):
            if None != re.search(route, row.act_name):
                print(f"{row.act_name} <= {role}")
                api.sql_void(conn, ins2, {"rn": role, "u": row.act_name})

    rows = api.sql_rows(conn, select_unroled)
    if len(rows) > 0:
        print("** Registered end-points not associated to a role **")
        for row in rows:
            print(row.act_name)


def load_essentials(conn):
    with conn.cursor() as cursor:
        ins = "insert into roles (role_name, sort) values (%s, %s)"
        cursor.executemany(ins, [SYS_ADMIN_ROLE, USER_ROLE])

    register_activities(conn)

    with conn.cursor() as cursor:
        ins = """
insert into roleactivities (roleid, activityid)
values (
    (select id from roles where role_name=%(rn)s),
    (select id from activities where act_name=%(u)s))"""
        for aname in USER_ACTS:
            cursor.execute(ins, {"rn": "User", "u": aname})
        for aname in SYS_ADMIN_ACTS:
            cursor.execute(ins, {"rn": "System Administrator", "u": aname})

    conn.commit()


def create_yenot_user(conn, user, pw):
    user = user.upper()

    with conn.cursor() as cursor:
        x = bcrypt.hashpw(pw.encode("utf8"), bcrypt.gensalt())
        x = x.decode("ascii")
        ins = "insert into users (username, pwhash) values (%s, %s)"
        cursor.execute(ins, (user, x))

    with conn.cursor() as cursor:
        ins = """
insert into userroles (roleid, userid)
values (
    (select id from roles where role_name=%(r)s),
    (select id from users where username=%(u)s))"""
        for role, _ in [SYS_ADMIN_ROLE, USER_ROLE]:
            cursor.execute(ins, {"r": role, "u": user})
    conn.commit()


def create_yenot_role(conn, role, sort=50):
    with conn.cursor() as cursor:
        ins = "insert into roles (role_name, sort) values (%s, %s)"
        cursor.execute(ins, (role, sort))
    conn.commit()
