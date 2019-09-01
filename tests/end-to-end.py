import os
import tempfile
import codecs
import sys
import json
import time
import concurrent.futures as futures
import rtlib
import yenot.client as yclient
import yenot.tests

TEST_DATABASE = 'yenot_e2e_test'

def test_url(dbname):
    if 'YENOT_DB_URL' in os.environ:
        return os.environ['YENOT_DB_URL']
    # Fall back to local unix socket.  This is the url for unix domain socket.
    return 'postgresql:///{}'.format(dbname)

def init_database(dburl):
    r = os.system('{} ../yenot/scripts/init-database.py {} --full-recreate \
            --ddl-script=schema/authentication.sql \
            --module=yenotauth.server --user=admin'.format(sys.executable, dburl))
    if r != 0:
        print('error exit')
        sys.exit(r)

class YASession(yclient.YenotSession):
    def authenticate_pin1(self, username, pin):
        p = {'username': username, 'pin': pin}
        try:
            r = self.post(self.prefix('api/session-by-pin'), data=p)
        except requests.ConnectionError:
            raise yclient.YenotServerError('The login server {} was unavailable.'.format(self.server_url))
        except requests.Timeout:
            raise yclient.YenotServerError('The login server {} was slow responding.'.format(self.server_url))
        if r.status_code not in (200, 210):
            raise yclient.YenotServerError('Login response failed from server {}.\n\n{}'.format(self.server_url, yclient.exception_string(r, 'POST')))
        elif r.status_code == 210:
            raise yclient.YenotError('Invalid user name or password.  Check your caps lock.')

        payload = yclient.StdPayload(r.text)

        # success
        self.yenot_sid = payload.keys['session']
        self.headers['X-Yenot-SessionId'] = self.yenot_sid
        return self.yenot_sid

    def authenticate_pin2(self, pin2):
        p = {'pin2': pin2}
        try:
            r = self.post(self.prefix('api/session/promote-2fa'), data=p)
        except requests.ConnectionError:
            raise yclient.YenotServerError('The login server {} was unavailable.'.format(self.server_url))
        except requests.Timeout:
            raise yclient.YenotServerError('The login server {} was slow responding.'.format(self.server_url))
        if r.status_code not in (200, 210):
            raise yclient.YenotServerError('Login response failed from server {}.\n\n{}'.format(self.server_url, yclient.exception_string(r, 'POST')))
        elif r.status_code == 210:
            raise yclient.YenotError('Invalid user name or password.  Check your caps lock.')

        payload = yclient.StdPayload(r.text)

        self.yenot_user = payload.keys['username']
        self.yenot_sid = payload.keys['session']
        self._capabilities = payload.named_table('capabilities')
        self.headers['X-Yenot-SessionId'] = self.yenot_sid
        return True

    def authenticate(self, username, password):
        p = {'username': username, 'password': password}
        try:
            r = self.post(self.prefix('api/session'), data=p)
        except requests.ConnectionError:
            raise yclient.YenotServerError('The login server {} was unavailable.'.format(self.server_url))
        except requests.Timeout:
            raise yclient.YenotServerError('The login server {} was slow responding.'.format(self.server_url))
        if r.status_code not in (200, 210):
            raise yclient.YenotServerError('Login response failed from server {}.\n\n{}'.format(self.server_url, yclient.exception_string(r, 'POST')))
        elif r.status_code == 210:
            raise yclient.YenotError('Invalid user name or password.  Check your caps lock.')

        payload = yclient.StdPayload(r.text)

        # success
        self.yenot_user = username.upper()
        self.yenot_sid = payload.keys['session']
        self._capabilities = payload.named_table('capabilities')
        self.headers['X-Yenot-SessionId'] = self.yenot_sid
        return True

    def close(self):
        if self.yenot_sid != None:
            r = self.put(self.prefix('api/session/logout'))
            if r.status_code != 200:
                raise yclient.raise_exception_ex(r, 'PUT')

        super(YASession, self).close()

def test_auth_fail(srvparams):
    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)
        client = session.std_client()

        error = False
        try:
            client.get('api/user/logged-in/reports')
        except yclient.YenotServerError as e:
            error = True
            assert e.status_code == 401
        assert error

def test_login_fail(srvparams):
    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)

        error = False
        try:
            session.authenticate('nonuser', 'happy')
        except yclient.YenotError as e:
            error = True
            assert str(e).startswith('Invalid')
        assert error

def test_login(srvparams):
    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)
        session.authenticate('admin', os.environ['INIT_DB_PASSWD'])

        client = session.std_client()
        content = client.get('api/sessions/active')
        assert content.main_table().rows[0].username == 'ADMIN'

        content = client.get('api/users/list')
        user1 = content.main_table().rows[0]
        client.get('api/users/lastlogin')
        content = client.get('api/roles/list')
        role1 = content.main_table().rows[0]
        client.get('api/activities/by-role', role=role1.id)
        client.get('api/users/by-role', role=role1.id)

        client.get('api/activities/list')

        client.get('api/userroles/by-users', users=user1.id)
        client.get('api/userroles/by-roles', roles=role1.id)
        client.get('api/roleactivities/by-roles', roles=role1.id)

        session.close()

def test_authorize_remainder(srvparams):
    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)
        session.authenticate('admin', os.environ['INIT_DB_PASSWD'])

        client = session.std_client()

        content = client.get('api/roles/list')
        admin = [role for role in content.main_table().rows if role.role_name == 'System Administrator'][0]

        content = client.get('api/roleactivities/by-roles', roles=admin.id)

        permitted = rtlib.simple_table(['id', 'permissions'])

        for row in content.main_table().rows:
            if row.permissions == None:
                with permitted.adding_row() as r2:
                    r2.id = row.id
                    adminper = {'roleid': admin.id, 'permitted': True}
                    r2.permissions = [adminper]

        client.put('api/roleactivities/by-roles', roles=admin.id,
                files={'roleactivities': permitted.as_http_post_file()})

        # now look, I'm permitted
        client.get('api/endpoints')
        client.get('api/user/logged-in/reports')

        session.close()

def test_crud_roles(srvparams):
    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)
        session.authenticate('admin', os.environ['INIT_DB_PASSWD'])

        client = session.std_client()

        content = client.get('api/role/new')
        rtable = content.main_table()
        role = rtable.rows[0]
        role.role_name = 'My Test Role'
        role.sort = 50
        client.put('api/role/{}', role.id, files={'role': rtable.as_http_post_file()})

        content = client.get('api/users/list')
        admin = [user for user in content.main_table().rows if user.username == 'ADMIN'][0]

        content = client.get('api/userroles/by-users', users=admin.id)

        permitted = rtlib.simple_table(['id', 'user_list'])

        for row in content.main_table().rows:
            if row.user_list == None or row.user_list.find(admin.id) < 0:
                with permitted.adding_row() as r2:
                    r2.id = row.id
                    r2.user_list = [admin.id]

        client.put('api/userroles/by-users', users=admin.id,
                files={'userroles': permitted.as_http_post_file()})

        # now read, delete the role that I just added myself to!?!
        content = client.get('api/roles/list')
        mtr = [role for role in content.main_table().rows if role.role_name == 'My Test Role'][0]
        client.get('api/role/{}', mtr.id)
        client.delete('api/role/{}', mtr.id)

        session.close()

def test_change_pin(server, uname, pword):
    if True:
        # want to indent at same level as everything else
        session = YASession(server.url)
        session.authenticate(uname, pword)

        client = session.std_client()

        data = {
                'oldpass': pword,
                'newpin': '23456',
                'target_2fa': json.dumps({'file': None})}
        client.post('api/user/me/change-pin', data=data)

        try:
            data = {
                    'oldpass': 'wrong password',
                    'newpass': 'test2345'}
            client.post('api/user/me/change-password', data=data)
        except yclient.YenotError as e:
            assert str(e).find('does not match') >= 0

        data = {
                'oldpass': pword,
                'newpass': 'test2345'}
        client.post('api/user/me/change-password', data=data)

        session.close()

        # log in with the pin
        session = YASession(server.url)
        try:
            session.authenticate_pin1(uname, '2xy56')
        except yclient.YenotError as e:
            assert str(e).startswith('Invalid')

        session.authenticate_pin1(uname, '23456')
        # read pin from file!!
        seg = codecs.encode(session.yenot_sid.encode('ascii'), 'hex').decode('ascii')
        fname = os.path.join(os.environ['YENOT_2FA_DIR'], 'authpin-{}'.format(seg))
        pin2 = open(fname, 'r').read()
        session.authenticate_pin2(pin2)

        session.close()

def test_crud_users(srvparams):
    tdir = tempfile.TemporaryDirectory()
    os.environ['YENOT_2FA_DIR'] = tdir.name

    with yenot.tests.server_running(**srvparams) as server:
        session = YASession(server.url)
        session.authenticate('admin', os.environ['INIT_DB_PASSWD'])

        client = session.std_client()

        content = client.get('api/roles/list')
        roles = content.main_table()
        roles = [r for r in roles.rows if r.role_name == 'User']

        user = rtlib.simple_table(['username', 'full_name', 'password', 'roles'])
        with user.adding_row() as r2:
            r2.username = 'Test1'
            r2.full_name = 'Test X. Person'
            r2.password = 'test1234'
            r2.roles = [r.id for r in roles]
        client.post('api/user', files={'user': user.as_http_post_file()})

        test_change_pin(server, 'test1', 'test1234')

        content = client.get('api/userroles/by-roles', roles=roles[0].id)

        permitted = rtlib.simple_table(['id', 'role_list'])

        for row in content.main_table().rows:
            if row.role_list == None or row.role_list.find(roles[0].id) < 0:
                with permitted.adding_row() as r2:
                    r2.id = row.id
                    r2.role_list = [r.id for r in roles]

        client.put('api/userroles/by-roles', roles=roles[0].id,
                files={'userroles': permitted.as_http_post_file()})

        content = client.get('api/users/list')
        test = [user for user in content.main_table().rows if user.username == 'TEST1'][0]
        client.get('api/user/{}', test.id)
        client.delete('api/user/{}', test.id)

        session.close()

    tdir.cleanup()

if __name__ == '__main__':
    srvparams = {
            'dburl': test_url(TEST_DATABASE),
            'modules': ['yenotauth.server']}

    init_database(test_url(TEST_DATABASE))
    test_auth_fail(srvparams)
    test_login_fail(srvparams)
    test_login(srvparams)
    test_authorize_remainder(srvparams)
    test_crud_roles(srvparams)
    test_crud_users(srvparams)
