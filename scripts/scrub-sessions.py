import os
import requests
import yenot.backend
import yenot.backend.api as api

SELECT_UNUSED_DEVICE_TOKENS = """
with dt_delete_queue as (
    select
        devicetokens.id, devicetokens.userid, devicetokens.device_name,
        devicetokens.issued, devicetokens.expires, 
        devicetokens.inactive,
        x.last_session_expires,
        case
            when devicetokens.inactive then true
            when devicetokens.expires < current_timestamp - interval '15 days' then true
            when coalesce(x.last_session_expires, devicetokens.issued) < current_timestamp - interval '60 days' then true
            else false end as to_delete
    from devicetokens
    left outer join lateral (
        select devicetokens.id, sessions.expires as last_session_expires
        from devicetokens
        join sessions on sessions.devtok_id=devicetokens.id
        left outer join sessions s2 on s2.devtok_id=devicetokens.id and s2.expires > sessions.expires
        where s2.devtok_id is null
        ) x on x.id=devicetokens.id
    order by devicetokens.issued
)
delete from devicetokens where devicetokens.id in (select id from dt_delete_queue where to_delete)
returning *;
"""


SELECT_OLD_SESSIONS = """
delete
from sessions
where expires < current_timestamp - interval '14 days'
returning *
"""


def main():
    conn = yenot.backend.create_connection(os.environ["LMS_PROD_DB"])

    rows = api.sql_rows(conn, SELECT_OLD_SESSIONS)
    print(f"Removed {len(rows)} stale sessions.")

    rows = api.sql_rows(conn, SELECT_UNUSED_DEVICE_TOKENS)
    print(f"Removed {len(rows)} stale device tokens.")

    conn.commit()
    conn.close()

    canary = os.getenv("CANARY_URL_SCRUB_SESSIONS")
    if canary:
        requests.get(canary)


if __name__ == "__main__":
    main()
