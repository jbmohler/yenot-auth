import sys
import yenotauth.initdb as initdb

conn = initdb.create_connection(sys.argv[1])
try:
    initdb.create_yenot_role(conn, sys.argv[2])
finally:
    conn.close()
