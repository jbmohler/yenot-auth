import sys
import getpass
import argparse
import initdb

password = getpass.getpass()
conn = initdb.create_connection(sys.argv[1])
try:
    #with conn.cursor() as cursor:
    #    cursor.execute("select * from pg_tables")
    #    for row in cursor.fetchall():
    #        print(row)

    initdb.create_yenot_user(conn, sys.argv[2], password)
finally:
    conn.close()
