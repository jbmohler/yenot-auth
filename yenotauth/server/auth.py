import os
import json
import uuid
import datetime
import random
import bcrypt
import base64
import psycopg2.extras
from bottle import request, response, HTTPError
import rtlib
import yenot.backend.api as api

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

@app.post('/api/user', name='post_api_user')
def post_api_user():
    user = api.table_from_tab2('user', amendments=['id'])

    if len(user.rows) != 1:
        raise api.UserError('invalid-input', 'Exactly one user required.')

    insroles = """
insert into userroles (userid, roleid)
select (select id from users where username=%(un)s), rl.rl::uuid
from unnest(%(roles)s) rl"""

    with app.dbconn() as conn:
        columns = []
        for c in user.DataRow.__slots__:
            if c == 'password':
                columns.append('pwhash')
            elif c == 'pin':
                columns.append('pinhash')
            elif c != 'roles':
                columns.append(c)

        tt = rtlib.simple_table(columns)
        for row in user.rows:
            with tt.adding_row() as r2:
                for c in user.DataRow.__slots__:
                    if c == 'password':
                        hashed = bcrypt.hashpw(row.password.encode('utf8'), bcrypt.gensalt())
                        hashed = hashed.decode('ascii')
                        r2.pwhash = hashed
                    elif c == 'pin':
                        hashed = bcrypt.hashpw(row.pin.encode('utf8'), bcrypt.gensalt())
                        hashed = hashed.decode('ascii')
                        r2.pinhash = hashed
                    elif c == 'id' and getattr(row, 'id', None) == None:
                        r2.id = None
                    elif c == 'username':
                        r2.username = row.username.upper()
                    elif c == 'target_2fa':
                        r2.target_2fa = psycopg2.extras.Json(row.target_2fa)
                    else:
                        setattr(r2, c, getattr(row, c))

        with api.writeblock(conn) as w:
            w.upsert_rows('users', tt)

        if 'roles' in user.DataRow.__slots__:
            api.sql_void(conn, insroles, {'un': tt.rows[0].username, 'roles': user.rows[0].roles})

        conn.commit()
    return api.Results().json_out()

@app.post('/api/user/me/change-password', name='api_user_me_change_password')
def api_user_me_change_password():
    oldpass = request.forms.get('oldpass')
    newpass = request.forms.get('newpass')

    select = """
select id, username, pwhash, inactive
from users
where id=(select userid from sessions where sessions.id=%(sid)s)"""

    update = """
update users set pwhash=%(h)s where id=%(i)s"""

    with app.dbconn() as conn:
        user = api.sql_1object(conn, select, {'sid': request.headers['X-Yenot-SessionID']})

        if user == None:
            raise api.UserError('invalid-user', 'Cannot find the record for the password change')

        if bcrypt.hashpw(oldpass.encode('utf8'), user.pwhash.encode('utf8')) != user.pwhash.encode('utf8'):
            raise api.UserError('invalid-password', 'old password does not match')

        hashed = bcrypt.hashpw(newpass.encode('utf8'), bcrypt.gensalt())
        hashed = hashed.decode('ascii')

        api.sql_void(conn, update, {'h': hashed, 'i': user.id})
        conn.commit()
    return api.Results().json_out()

@app.post('/api/user/me/change-pin', name='api_user_me_change_pin')
def api_user_me_change_pin():
    oldpass = request.forms.get('oldpass')
    newpin = request.forms.get('newpin')
    t2fa = json.loads(request.forms.get('target_2fa'))

    select = """
select id, username, pwhash, inactive
from users
where id=(select userid from sessions where sessions.id=%(sid)s)"""

    update = """
update users set pinhash=%(h)s, target_2fa=%(fa)s where id=%(i)s"""

    with app.dbconn() as conn:
        user = api.sql_1object(conn, select, {'sid': request.headers['X-Yenot-SessionID']})

        if user == None:
            raise api.UserError('invalid-user', 'Cannot find the record for the pin change')

        if bcrypt.hashpw(oldpass.encode('utf8'), user.pwhash.encode('utf8')) != user.pwhash.encode('utf8'):
            raise api.UserError('invalid-pin', 'old pin does not match')

        hashed = bcrypt.hashpw(newpin.encode('utf8'), bcrypt.gensalt())
        hashed = hashed.decode('ascii')

        x = psycopg2.extras.Json(t2fa)
        api.sql_void(conn, update, {'h': hashed, 'i': user.id, 'fa': x})
        conn.commit()
    return api.Results().json_out()

@app.post('/api/session', name='api_session', skip=['yenot-auth'])
def api_session():
    username = request.forms.get('username')
    password = request.forms.get('password')
    ip = request.environ.get('REMOTE_ADDR')

    select = 'select id, username, pwhash, inactive from users where username=%(uname)s'
    sess_insert = """
insert into sessions (id, userid, ipaddress, refreshed)
values (%(sid)s, %(uid)s, %(ip)s, current_timestamp);"""

    results = api.Results()
    with app.dbconn() as conn:
        rows = api.sql_rows(conn, select, {'uname': username.upper()})

        content = {}

        if len(rows) == 0:
            content['status'] = 'no user by that name'
            status = 210
        elif rows[0].inactive:
            content['status'] = 'inactive'
            status = 210
        elif bcrypt.hashpw(password.encode('utf8'), rows[0].pwhash.encode('utf8')) != rows[0].pwhash.encode('utf8'):
            content['status'] = 'incorrect password'
            status = 210
        else:
            content['status'] = 'welcome {}'.format(rows[0].username)
            status = 200

        if status == 200:
            # generate and write session
            session = base64.b64encode(os.urandom(18)).decode('ascii')  # 24 characters
            assert len(session) == 24
            content['session'] = session
            params = {
                    'sid': session, 
                    'uid': rows[0].id, 
                    'ip': ip}
            api.sql_void(conn, sess_insert, params)
            conn.commit()

            capabilities = api.sql_tab2(conn, CAPS_SELECT, {'sid': session})

            content['capabilities'] = capabilities

        results.keys.update(content)

    response.status = status
    return results.json_out()

@app.post('/api/session-by-pin', name='api_session_by_pin', skip=['yenot-auth'])
def api_session_by_pin():
    username = request.forms.get('username')
    pin = request.forms.get('pin')
    ip = request.environ.get('REMOTE_ADDR')

    select = 'select id, username, pinhash, target_2fa, inactive from users where username=%s'
    sess_insert = """
insert into sessions (id, userid, ipaddress, refreshed, inactive, pin_2fa)
values (%(sid)s, %(uid)s, %(ip)s, %(to)s, true, %(pin6)s);"""

    status = 403
    results = api.Results()
    with app.dbconn() as conn:
        cursor = conn.cursor()
        cursor.execute(select, [username.upper()])
        rows = cursor.fetchall()

        if len(rows) == 0:
            results.keys['status'] = 'no user by that name'
            status = 210
        elif rows[0].inactive:
            results.keys['status'] = 'inactive'
            status = 210
        elif rows[0].pinhash == None:
            results.keys['status'] = 'no pin login for this user'
            status = 210
        elif bcrypt.hashpw(pin.encode('utf8'), rows[0].pinhash.encode('utf8')) != rows[0].pinhash.encode('utf8'):
            results.keys['status'] = 'incorrect pin'
            status = 210
        else:
            results.keys['status'] = 'welcome {}'.format(rows[0].username)
            status = 200

        pin6 = [str(random.randint(0, 9)) for _ in range(6)]

        if status == 200:
            # generate and write session
            session = base64.b64encode(os.urandom(18)).decode('ascii')  # 24 characters
            assert len(session) == 24
            results.keys['session'] = session
            params = {
                    'sid': session, 
                    'uid': rows[0].id, 
                    'ip': ip, 
                    'to': datetime.datetime.utcnow(),
                    'pin6': ''.join(pin6)}
            cursor.execute(sess_insert, params)
            conn.commit()

            t2fa = rows[0].target_2fa
            if 'file' in t2fa:
                import codecs
                with open('./opslogs/mypin-{}.txt'.format(codecs.encode(session.encode('ascii'), 'hex').decode('ascii')), 'w') as f:
                    f.write(''.join(pin6))
            if 'sms' in t2fa:
                from twilio.rest import Client
                # put your own credentials here

                account_sid = app.config['twilio'].account_sid
                auth_token = app.config['twilio'].auth_token
                src_phone = app.config['twilio'].src_phone

                pin6s = '{} {}'.format(''.join(pin6[:3]), ''.join(pin6[3:]))
                client = Client(account_sid, auth_token)
                client.messages.create(
                            to=t2fa['sms'],
                            from_=src_phone,
                            body='Your one-time PIN is {}'.format(pin6s))

        cursor.close()

    response.status = status
    return results.json_out()

@app.post('/api/session/promote-2fa', name='api_session_promote_2fa', skip=['yenot-auth'])
def api_session_promote_2fa():
    session = request.headers['X-Yenot-SessionID']
    pin2 = request.forms.get('pin2')

    username = request.params.get('username', None)
    ip = request.environ.get('REMOTE_ADDR')

    select = 'select * from sessions where id=%(sid)s'
    sess_insert = """
insert into sessions (id, userid, ipaddress, refreshed)
values (%(sid)s, %(uid)s, %(ip)s, %(to)s);"""

    results = api.Results()
    with app.dbconn() as conn:
        sessrow = api.sql_1object(conn, select, {'sid': session})

        if sessrow != None:
            if sessrow.pin_2fa == pin2:
                status = 200
            else:
                status = 210
        else:
            status = 401

        if status == 200:
            # generate and write session
            session = base64.b64encode(os.urandom(18)).decode('ascii')  # 24 characters
            assert len(session) == 24
            results.keys['session'] = session
            api.sql_void(conn, sess_insert, {'sid': session, 'uid': sessrow.userid, 'ip': ip, 'to': datetime.datetime.utcnow()})
            conn.commit()

            capabilities = api.sql_tab2(conn, CAPS_SELECT, {'sid': session})

            results.keys['username'] = api.sql_1row(conn, "select username from users join sessions on sessions.userid=users.id where sessions.id=%(sid)s", {'sid': session})
            results.keys['capabilities'] = capabilities

    response.status = status
    return results.json_out()

@app.put('/api/session/logout', name='api_session_logout')
def api_session_logout():
    session = request.headers['X-Yenot-SessionID']

    update = """
update sessions set inactive=true where id=%(sid)s"""

    with app.dbconn() as conn:
        api.sql_void(conn, update, {'sid': session})
        conn.commit()
    return api.Results().json_out()

@app.get('/api/sessions/active', name='get_api_sessions_active')
def get_api_sessions_active():
    select = """
select users.id, users.username, sessions.ipaddress, sessions.refreshed
from sessions
join users on users.id=sessions.userid
where not sessions.inactive
"""

    cm = {\
            'id': {'type': 'yenot_user.surrogate'},
            'name': {'type': 'yenot_user.name', 'url_key': 'id'},
            'ipaddress': {'label': 'IP Address'}}

    results = api.Results()
    with app.dbconn() as conn:
        results.tables['sessions', True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()

def get_users_prompts():
    cm = {\
            'include_inactive': {'type': 'boolean', 'default': False},
            'userrole': {'label': 'Role', 'type': 'yenot_role.surrogate'}}
    return [(a, cm.get(a, None)) for a in ['include_inactive', 'userrole']]

@app.get('/api/users', name='api_users', \
        report_title='User List', report_prompts=get_users_prompts)
def get_users():
    iinactive = api.parse_bool(request.params.get('include_inactive', False))
    userrole = request.params.get('userrole', None)

    select = """
select users.id, users.username, users.full_name, 
    users.descr as description, users.inactive, 
    loggedin.count, userroles2.rolenames as roles
from users
left outer join (select userid, count(*) from sessions where not inactive group by userid) as loggedin on loggedin.userid=users.id
left outer join (
    select 
        userid, 
        string_agg(roles.role_name, '; ' order by role_name) as rolenames
    from userroles 
    join roles on roles.id=userroles.roleid
    group by userid) as userroles2 on userroles2.userid=users.id
/*WHERE*/
order by users.username
"""

    wheres = []
    params = {}
    if userrole not in ('', None):
        wheres.append('users.id in (select userroles.userid from userroles where userroles.roleid=%(ri)s)')
        params['ri'] = userrole
    if not iinactive:
        wheres.append('not users.inactive')

    if len(wheres) > 0:
        select = select.replace('/*WHERE*/', 'where ' + ' and '.join(wheres))

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_user.surrogate'},
                'username': {'type': 'yenot_user.name', 'url_key': 'id', 'represents': True},
                'count': {'label': 'Active Sessions'}}
        results.tables['users', True] = api.sql_tab2(conn, select, params, cm)
    return results.json_out()

@app.get('/api/users/lastlogin', name='api_users_lastlogin', \
        report_title='User List by Last Login')
def get_users_lastlogin():
    select = """
select users.id, users.username, lastlog.ipaddress, lastlog.refreshed, active.count as active_count
from users
join lateral (
    select sessions.ipaddress, sessions.refreshed
    from sessions
    where sessions.userid=users.id
    order by refreshed desc
    limit 1) lastlog on true
left outer join lateral (
    select count(*)
    from sessions
    where sessions.userid=users.id and not sessions.inactive) as active on true
order by users.username"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_user.surrogate'},
                'username': {'type': 'yenot_user.name', 'url_key': 'id', 'represents': True},
                'active_count': {'label': 'Active Sessions'}}

        results.tables['logins', True] = api.sql_tab2(conn, select, column_map=cm)
    return results.json_out()

def get_activities_by_role_prompts():
    return []

@app.get('/api/activities/by-role', name='api_activities_by_role', \
        hide_report=True,
        report_title='Activities for Role', report_prompts=get_activities_by_role_prompts)
def get_activities_by_role():
    role_id = request.query.get('role', None)

    select = """
select activities.id, activities.description, activities.act_name, activities.url
from roles
join roleactivities on roleactivities.roleid=roles.id
join activities on activities.id=roleactivities.activityid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_role.surrogate'},
                'username': {'label': 'Role', 'type': 'yenot_role.name', 'url_key': 'id', 'represents': True},
                'full_namel': {'label': 'Activities'}}

        results.tables['activities', True] = api.sql_tab2(conn, select, {'r': role_id}, cm)

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += 'Activities for Role {}'.format(rn)

    return results.json_out()

def get_users_by_role_prompts():
    return []

@app.get('/api/users/by-role', name='api_users_by_role', \
        hide_report=True,
        report_title='Users for Role', report_prompts=get_users_by_role_prompts)
def get_users_by_role():
    role_id = request.query.get('role', None)

    select = """
select users.id, users.username, users.full_name, users.inactive
from roles
join userroles on userroles.roleid=roles.id
join users on users.id=userroles.userid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_role.surrogate'},
                'username': {'label': 'Role', 'type': 'yenot_role.name', 'url_key': 'id', 'represents': True},
                'full_namel': {'label': 'Users'}}

        results.tables['users', True] = api.sql_tab2(conn, select, {'r': role_id}, cm)

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += 'Users for Role {}'.format(rn)

    return results.json_out()

@app.get('/api/role/<roleid>/record', name='get_api_role_record')
def get_api_role_record(roleid):
    select = """
select roles.id, roles.role_name, roles.sort
from roles
where roles.id=%(r)s
"""

    cm = {\
            'id': {'type': 'yenot_role.surrogate'},
            'role_name': {'label': 'Role', 'type': 'yenot_role.name', 'url_key': 'id', 'represents': True}}

    results = api.Results()
    with app.dbconn() as conn:
        results.tables['role'] = api.sql_tab2(conn, select, {'r': roleid}, cm)
    return results.json_out()

@app.get('/api/roles/list', name='get_api_roles_list')
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

    cm = {\
            'id': {'type': 'yenot_role.surrogate'},
            'role_name': {'label': 'Role', 'type': 'yenot_role.name', 'url_key': 'id', 'represents': True},
            'count': {'label': 'Users'}}

    results = api.Results()
    with app.dbconn() as conn:
        results.tables['roles', True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()

@app.put('/api/roles', name='put_api_roles')
def put_api_roles():
    coll = api.table_from_tab2('rolelist', amendments=['id'], required=['role_name', 'sort'])

    for row in coll.rows:
        if not hasattr(row, 'id'):
            row.id = str(uuid.uuid1())

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows('roles', coll)
        conn.commit()
    return api.Results().json_out()

@app.delete('/api/role/<roleid>', name='delete_api_role')
def delete_api_role(roleid):
    # consider using cascade
    delete = """
delete from roleactivities where roleid=%(r)s;
delete from userroles where roleid=%(r)s;
delete from roles where id=%(r)s;
"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {'r': roleid})
        conn.commit()
    return api.Results().json_out()

@app.get('/api/activities/list', name='get_api_activities_list')
def get_api_activities_list():
    select = """
select activities.id, activities.act_name, activities.description, activities.url
from activities
"""

    cm = {\
            'id': {'type': 'yenot_role.surrogate'},
            'name': {'type': 'yenot_role.name', 'url_key': 'id', 'represents': True},
            'count': {'label': 'Users'}}

    results = api.Results()
    with app.dbconn() as conn:
        results.tables['activities', True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()

@app.put('/api/activities', name='put_api_activities')
def put_api_activities():
    activities = api.table_from_tab2('activities', amendments=['id'], required=['act_name', 'description'], allow_extra=True)

    for row in activities.rows:
        if not hasattr(row, 'id'):
            row.id = uuid.uuid1().hex

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows('activities', activities)
        conn.commit()
    return api.Results().json_out()

@app.get('/api/activity/<activityid>/record', name='get_api_activity_record')
def get_api_activity_record(activityid):
    select = """
select activities.id, activities.act_name, activities.description, activities.note
from activities
where activities.id=%(r)s
"""

    cm = {\
            'id': {'type': 'yenot_activity.surrogate'},
            'name': {'label': 'Activity', 'type': 'yenot_activity.name', 'url_key': 'id', 'represents': True}}

    results = api.Results()
    with app.dbconn() as conn:
        results.tables['activity'] = api.sql_tab2(conn, select, {'r': activityid}, cm)
    return results.json_out()


@app.get('/api/userroles/by_users', name='api_userroles_by_users')
def get_userroles_by_users():
    # comma delimited list of user ids
    users = request.params.get('users').split(',')
    users = list(users)

    select = """
with users_universe as (
    select unnest(%(users)s)::uuid as userid
)
select roles.id, roles.role_name, u2.user_list
from roles
left outer join (
                    select roleid, array_agg(userroles.userid) as user_list
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
        cm = {\
                'id': {'type': 'yenot_role.surrogate'},
                'name': {'type': 'yenot_role.name', 'url_key': 'id', 'represents': True}}
        p = {'users': users}
        results.tables['users', True] = api.sql_tab2(conn, select, p, cm)
        results.tables['usernames'] = api.sql_tab2(conn, select2, p)
    return results.json_out()

@app.put('/api/userroles/by_users', name='put_api_userroles_by_users')
def put_userroles_by_users():
    coll = api.table_from_tab2('userroles', required=['id', 'user_list'])
    # comma delimited list of user ids
    users = request.forms.get('users').split(',')
    users = list(users)

    insert = """
-- insert role--user links for all users in universe not yet linked to role.
with users_add as (
    select * from (select unnest(%(users)s) as userid) as f
    where f.userid = any(%(tolink)s)
), toinsert as (
    select %(id)s, users_add.userid
    from users_add
    left outer join userroles on userroles.roleid=%(id)s and userroles.userid=users_add.userid
    where userroles.userid is null
)
insert into userroles (roleid, userid)
(select * from toinsert)"""

    delete = """
-- insert role--user links for all users in universe not yet linked to role.
with users_del as (
    select * from (select unnest(%(users)s) as userid) as f
    where f.userid <> all(%(tolink)s)
)
delete from userroles where userroles.roleid=%(id)s and 
                            userroles.userid in (select userid from users_del)"""

    with app.dbconn() as conn:
        cursor = conn.cursor()

        for row in coll.rows:
            params = { \
                    'users': users,
                    'tolink': list(row.user_list),
                    'id': row.id}

            cursor.execute(insert, params)
            cursor.execute(delete, params)

        conn.commit()
        cursor.close()

    return api.Results().json_out()

@app.get('/api/userroles/by_roles', name='api_userroles_by_roles')
def get_userroles_by_roles():
    # comma delimited list of user ids
    roles = request.params.get('roles').split(',')
    roles = list(roles)

    select = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select users.id, users.username, u2.role_list
from users
left outer join (
                    select userid, array_agg(userroles.roleid) as role_list
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
    results.key_labels += 'Users for Role(s)'
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_user.surrogate'},
                'name': {'type': 'yenot_user.name', 'url_key': 'id', 'represents': True}}
        p = {'roles': roles}
        results.tables['users', True] = api.sql_tab2(conn, select, p, cm)
        results.tables['rolenames'] = api.sql_tab2(conn, select2, p)
    return results.json_out()

@app.put('/api/userroles/by_roles', name='put_api_userroles_by_roles')
def put_userroles_by_roles():
    coll = api.table_from_tab2('userroles', required=['id', 'role_list'])
    # comma delimited list of user ids
    roles = request.forms.get('roles').split(',')
    roles = list(roles)

    insert = """
-- insert role--user links for all roles in universe not yet linked to role.
with roles_add as (
    select * from (select unnest(%(roles)s) as roleid) as f
    where f.roleid = any(%(tolink)s)
), toinsert as (
    select %(id)s, roles_add.roleid
    from roles_add
    left outer join userroles on userroles.userid=%(id)s and userroles.roleid=roles_add.roleid
    where userroles.roleid is null
)
insert into userroles (userid, roleid)
(select * from toinsert)"""

    delete = """
-- insert role--user links for all users in universe not yet linked to role.
with roles_del as (
    select * from (select unnest(%(roles)s) as roleid) as f
    where f.roleid <> all(%(tolink)s)
)
delete from userroles where userroles.userid=%(id)s and 
                            userroles.roleid in (select roleid from roles_del)"""

    with app.dbconn() as conn:
        cursor = conn.cursor()

        for row in coll.rows:
            params = { \
                    'roles': roles,
                    'tolink': list(row.role_list),
                    'id': row.id}

            cursor.execute(insert, params)
            cursor.execute(delete, params)

        conn.commit()
        cursor.close()

    return api.Results().json_out()

@app.get('/api/roleactivities/by_roles', name='api_roleactivities_by_roles')
def get_roleactivities_by_roles():
    # comma delimited list of role ids
    roles = request.params.get('roles').split(',')
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
    results.key_labels += 'Activities for Role(s)'
    with app.dbconn() as conn:
        cm = {\
                'id': {'type': 'yenot_activity.surrogate'},
                'name': {'label': 'Activity', 'type': 'yenot_activity.name', 'url_key': 'id', 'represents': True}}
        p = {'roles': roles}
        results.tables['activities', True] = api.sql_tab2(conn, select, p, cm)
        results.tables['rolenames'] = api.sql_tab2(conn, select2, p)
    return results.json_out()

@app.put('/api/roleactivities/by_roles', name='put_api_roleactivities_by_roles')
def put_api_roleactivities_by_roles():
    coll = api.table_from_tab2('roleactivities', required=['id', 'permissions'])
    # comma delimited list of role ids
    roles = request.forms.get('roles').split(',')
    roles = list(roles)

    for row in coll.rows:
        if not hasattr(row, 'id'):
            row.id = uuid.uuid1().hex

    values = """(%(roleid)s::uuid, %(permitted)s, %(dashboard)s, %(dashprompts)s)"""

    update = """
-- update activity--role links for all roles in universe linked with some prior values.
with permissions(roleid, permitted, dashboard, dashprompts) as (
    values/*represented*/
), toupdate as (
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
with permissions(roleid, permitted, dashboard, dashprompts) as (
    values/*represented*/
), toinsert as (
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
        cursor = conn.cursor()
        # TODO:  use upsert
        cursor.execute("set transaction isolation level serializable")

        for row in coll.rows:
            represented = [r['roleid'] for r in row.permissions]

            mogrifications = []
            for passed in row.permissions:
                if passed['roleid'] not in roles:
                    raise RuntimeError('roles parameter establishes universe of allowed values')
                p = { \
                        'roleid': passed['roleid'],
                        'permitted': passed.get('permitted', False), 
                        'dashboard': passed.get('dashboard', False), 
                        'dashprompts': passed.get('dashprompts', None)}
                if p['dashprompts'] != None:
                    p['dashprompts'] = psycopg2.extras.Json(p['dashprompts'])
                mogrifications.append(cursor.mogrify(values, p))
            mogrifications = ','.join([x.decode('ascii') for x in mogrifications])

            # TODO: fix the ugly requirement for something to be in tolink param of delete:
            params = { \
                    'roles': roles,
                    'tolink': tuple(represented) if len(represented) > 0 else ('__bug_happens_here__',),
                    'id': row.id}

            # delete
            cursor.execute(delete, params)
            if len(represented) > 0:
                # update
                my_update = update.replace('/*represented*/', mogrifications)
                cursor.execute(my_update, params)
                # insert
                my_insert = insert.replace('/*represented*/', mogrifications)
                cursor.execute(my_insert, params)

        conn.commit()
        cursor.close()

    return api.Results().json_out()
