import os
import sys
import argparse
import importlib
import initdb

if __name__ == '__main__':
    parse = argparse.ArgumentParser('initialize a yenot database')
    parse.add_argument('dburl', 
            help='database identifier in url form (e.g. postgresql://user@host/dbname)')
    parse.add_argument('--module', 
            action='append', default=[],
            help='specify module to import before starting yenot server')
    parse.add_argument('--route', 
            action='append', default=[],
            help='add route and role arguments in pairs -- unregistered routes matching the regex are added to the role')
    parse.add_argument('--role', 
            action='append', default=[],
            help='add route and role arguments in pairs -- unregistered routes matching the regex are added to the role')

    args = parse.parse_args()

    if len(args.route) != len(args.role):
        parse.print_help()
        sys.exit(1)

    conn = initdb.create_connection(args.dburl)
    try:
        import yenot.backend
        app = yenot.backend.init_application(args.dburl)

        import yenot.server
        for m in args.module:
            importlib.import_module(m)

        initdb.register_activities(conn)
        initdb.rolemap_activities(conn, args.route, args.role)
        conn.commit()
    finally:
        conn.close()

