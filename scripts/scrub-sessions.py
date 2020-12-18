import os
import requests
import yenot.backend
import yenot.backend.api as api

SELECT_OLD_SESSIONS = """
delete
from sessions
where refreshed < current_timestamp - interval '14 days'
returning *
"""

def main():
    conn = yenot.backend.create_connection(os.environ["LMS_PROD_DB"])

    rows = api.sql_rows(conn, SELECT_OLD_SESSIONS)
    conn.commit()
    print(f"Removed {len(rows)} stale sessions.")

    conn.close()

    requests.get("https://hc-ping.com/12a5fa9a-79ee-4afe-9f9b-acc8e03eecc6")

if __name__ == '__main__':
    main()
