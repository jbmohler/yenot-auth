import sys
import getpass
import yenotauth.initdb as initdb

password = getpass.getpass()
conn = initdb.create_connection(sys.argv[1])
try:
    initdb.create_yenot_user(conn, sys.argv[2], password)
finally:
    conn.close()
