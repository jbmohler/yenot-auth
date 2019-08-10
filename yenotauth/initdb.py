import re
import bcrypt
import urllib.parse
import psycopg2
import psycopg2.extras
import yenot.backend.api as api

SYS_ADMIN_ROLE = ('System Administrator', 999)
USER_ROLE = ('User', 1)

USER_ACTS = [\
        #'api_user_reports',
        #'api_report_runmeta', 
        #'api_report_info',
        #'api_info',
        'api_user_me_change_password',
        'api_user_me_change_pin',
        'api_endpoints',
        'api_session_logout']

SYS_ADMIN_ACTS = [\
        'api_session',
        'api_session_by_pin',
        'api_session_promote_2fa',
        'api_session_logout',
        'get_api_sessions_active',
        'api_users_list',
        'api_users_lastlogin',
        'api_activities_by_role',
        'api_users_by_role',
        'get_api_role_record',
        'get_api_roles_list',
        'put_api_roles',
        'delete_api_role',
        'get_api_activities_list',
        'put_api_activities',
        'get_api_activity_record',
        'api_userroles_by_users',
        'put_api_userroles_by_users',
        'api_userroles_by_roles',
        'put_api_userroles_by_roles',
        'api_roleactivities_by_roles',
        'put_api_roleactivities_by_roles']

def register_activities(conn):
    app = api.get_global_app()

    with conn.cursor() as cursor:
        ins = """
insert into activities (act_name, description, url)
values(%(n)s, %(d)s, %(u)s)
on conflict (act_name) do nothing"""
        for ep in app.endpoints():
            cursor.execute(ins, {'n': ep.name, 'd': getattr(ep, 'config', {}).get('report_title', None), 'u': ep.url})

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
                print('{} <= {}'.format(row.act_name, role))
                api.sql_void(conn, ins2, {'rn': role, 'u': row.act_name})

    rows = api.sql_rows(conn, select_unroled)
    if len(rows) > 0:
        print('** Registered end-points not associated to a role **')
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
            print(aname)
            cursor.execute(ins, {'rn': 'User', 'u': aname})
        for aname in SYS_ADMIN_ACTS:
            cursor.execute(ins, {'rn': 'System Administrator', 'u': aname})

    conn.commit()

def create_yenot_user(conn, user, pw):
    user = user.upper()

    with conn.cursor() as cursor:
        x = bcrypt.hashpw(pw.encode('utf8'), bcrypt.gensalt())
        x = x.decode('ascii')
        ins = "insert into users (username, pwhash) values (%s, %s)"
        cursor.execute(ins, (user, x))

    with conn.cursor() as cursor:
        ins = """
insert into userroles (roleid, userid)
values (
    (select id from roles where role_name=%(r)s),
    (select id from users where username=%(u)s))"""
        for role, _ in [SYS_ADMIN_ROLE, USER_ROLE]:
            cursor.execute(ins, {'r': role, 'u': user})
    conn.commit()

def create_yenot_role(conn, role, sort=50):
    with conn.cursor() as cursor:
        ins = "insert into roles (role_name, sort) values (%s, %s)"
        cursor.execute(ins, (role, sort))
    conn.commit()
