import bcrypt

SYS_ADMIN_ROLE = ('System Administrator', 999)
USER_ROLE = ('User', 1)

USER_ACTS = [\
        #'api_user_reports',
        #'api_report_runmeta', 
        #'api_report_info',
        #'api_info',
        'api_session_logout']

SYS_ADMIN_ACTS = [\
        'api_user_me_change_password',
        'api_user_me_change_pin',
        'api_session',
        'api_session_by_pin',
        'api_session_promote_2fa',
        'api_session_logout',
        'get_api_sessions_active',
        'api_users',
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

def load_essentials(conn):
    with conn.cursor() as cursor:
        ins = "insert into roles (role_name, sort) values (%s, %s)"
        cursor.executemany(ins, [SYS_ADMIN_ROLE, USER_ROLE])

    import yenot.backend.api as api
    app = api.get_global_app()

    with conn.cursor() as cursor:
        ins = """
insert into activities (act_name, description, url)
values(%(n)s, %(d)s, %(u)s)"""
        for ep in app.endpoints():
            print(ep.name)
            cursor.execute(ins, {'n': ep.name, 'd': None, 'u': ep.url})

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
