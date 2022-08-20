import uuid
import yenot.backend.api as api

app = api.get_global_app()


def role_sidebar(idcolumn):
    return [{"name": "role_general", "on_highlight_row": {"id": idcolumn}}]


def activity_sidebar(idcolumn, namecolumn):
    return [
        {
            "name": "activity_general",
            "on_highlight_row": {"id": idcolumn, "act_name": namecolumn},
        }
    ]


def get_activities_by_role_prompts():
    return []


@app.get(
    "/api/activities/by-role",
    name="api_activities_by_role",
    hide_report=True,
    report_title="Activities for Role",
    report_prompts=get_activities_by_role_prompts,
)
def get_activities_by_role(request):
    role_id = request.query.get("role", None)

    select = """
select activities.id, activities.description, activities.act_name, activities.url
from roles
join roleactivities on roleactivities.roleid=roles.id
join activities on activities.id=roleactivities.activityid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
            url=api.cgen.auto(label="URL"),
        )

        results.tables["activities", True] = api.sql_tab2(
            conn, select, {"r": role_id}, cm
        )

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += f"Activities for Role {rn}"

    return results.json_out()


def get_users_by_role_prompts():
    return []


@app.get(
    "/api/users/by-role",
    name="api_users_by_role",
    hide_report=True,
    report_title="Users for Role",
    report_prompts=get_users_by_role_prompts,
)
def get_users_by_role(request):
    role_id = request.query.get("role", None)

    select = """
select users.id, users.username, users.full_name, users.inactive
from roles
join userroles on userroles.roleid=roles.id
join users on users.id=userroles.userid
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(
                label="Login Name", url_key="id", represents=True
            ),
        )

        results.tables["users", True] = api.sql_tab2(conn, select, {"r": role_id}, cm)

        rn = api.sql_1row(conn, "select role_name from roles where id=%s", (role_id,))
        results.key_labels += f"Users for Role {rn}"

    return results.json_out()


@app.get(
    "/api/roles/list",
    name="get_api_roles_list",
    report_title="Role List",
    report_sidebars=role_sidebar("id"),
)
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

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
            count=api.cgen.auto(label="Users", skip_write=True),
        )
        results.tables["roles", True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()


@app.get("/api/role/new", name="get_api_role_new")
def get_api_role_new():
    select = """
select roles.id, roles.role_name, roles.sort
from roles
where false
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
        )
        cols, rows = api.sql_tab2(conn, select, None, cm)

        def default_row(index, row):
            row.id = str(uuid.uuid1())

        rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["role", True] = cols, rows
    return results.json_out()


@app.get("/api/role/<roleid>", name="get_api_role_record")
def get_api_role_record(roleid):
    select = """
select roles.id, roles.role_name, roles.sort
from roles
where roles.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                label="Role", url_key="id", represents=True
            ),
        )

        results.tables["role", True] = api.sql_tab2(conn, select, {"r": roleid}, cm)
    return results.json_out()


@app.put("/api/role/<roleid>", name="put_api_role_record")
def put_api_role_record(roleid):
    role = api.table_from_tab2(
        "role", amendments=["id"], required=["role_name", "sort"]
    )

    if len(role.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one role required.")

    for row in role.rows:
        if not hasattr(row, "id"):
            row.id = roleid

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows("roles", role)
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/role/<roleid>", name="delete_api_role_record")
def delete_api_role_record(roleid):
    # consider using cascade
    delete = """
delete from roleactivities where roleid=%(r)s;
delete from userroles where roleid=%(r)s;
delete from roles where id=%(r)s;
"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"r": roleid})
        conn.commit()
    return api.Results().json_out()


@app.get(
    "/api/activities/list",
    name="get_api_activities_list",
    report_title="Activity List",
    report_sidebars=activity_sidebar("id", "act_name"),
)
def get_api_activities_list():
    select = """
select activities.id, activities.act_name, activities.description, activities.url
from activities
"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity Name", url_key="id", represents=True
            ),
            url=api.cgen.auto(label="URL"),
        )

        rawdata = api.sql_tab2(conn, select, None, cm)

        from . import endpoints

        xform = endpoints.ReportMetaXformer(None)
        columns = api.tab2_columns_transform(
            rawdata[0], insert=[("url", "method", "title", "prompts", "sidebars")]
        )

        def xform_rptmeta(oldrow, row):
            if row.act_name in xform.routes:
                row.method = xform.routes[row.act_name].method
                if "report_title" in xform.routes[row.act_name].config:
                    row.title = xform.routes[row.act_name].config["report_title"]

            xform.xform(oldrow, row)

        rows = api.tab2_rows_transform(rawdata, columns, xform_rptmeta)

        results.tables["activities", True] = columns, rows
    return results.json_out()


@app.post("/api/activities", name="post_api_activities")
def post_api_activities():
    activities = api.table_from_tab2(
        "activities",
        amendments=["id"],
        required=["act_name", "description"],
        allow_extra=True,
    )

    for row in activities.rows:
        if not hasattr(row, "id"):
            row.id = uuid.uuid1().hex

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows("activities", activities)
        conn.commit()
    return api.Results().json_out()


@app.get("/api/activity/<activityid>", name="get_api_activity_record")
def get_api_activity_record(activityid):
    select = """
select activities.id, activities.act_name, activities.description, activities.note
from activities
where activities.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
        )

        results.tables["activity", True] = api.sql_tab2(
            conn, select, {"r": activityid}, cm
        )
    return results.json_out()


@app.delete("/api/activity/<activityid>", name="delete_api_activity_record")
def delete_api_activity_record(activityid):
    delete = """
delete from roleactivities where activityid=%(r)s;
delete from activities where id=%(r)s;
"""

    results = api.Results()
    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"r": activityid})
        conn.commit()
    return results.json_out()


@app.get("/api/userroles/by-users", name="get_api_userroles_by_users")
def get_api_userroles_by_users(request):
    # comma delimited list of user ids
    users = request.params.get("users").split(",")
    users = list(users)

    select = """
with users_universe as (
    select unnest(%(users)s)::uuid as userid
)
select roles.id, roles.role_name, roles.sort,
    (
        select array_agg(userroles.userid::text) as users
        from userroles 
        join users_universe on users_universe.userid=userroles.userid
        where userroles.roleid=roles.id
    ) as users
from roles
order by sort
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
        cm = api.ColumnMap(
            id=api.cgen.yenot_role.surrogate(),
            role_name=api.cgen.yenot_role.name(
                url_key="id", represents=True, skip_write=True
            ),
            sort=api.cgen.auto(skip_write=True),
            users=api.cgen.matrix(),
        )

        p = {"users": users}
        results.tables["users", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["usernames"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/userroles/by-users", name="put_api_userroles_by_users")
def put_userroles_by_users(request):
    coll = api.table_from_tab2("roles", required=["id", "users"], matrix=["users"])
    # comma delimited list of user ids
    users = request.params.get("users").split(",")
    users = list(users)

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.update_rows("roles", coll, matrix={"users": "userroles"})
        conn.commit()

    return api.Results().json_out()


@app.get("/api/userroles/by-roles", name="get_api_userroles_by_roles")
def get_api_userroles_by_roles(request):
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    select = """
with roles_universe as (
    select unnest(%(roles)s::uuid[]) as roleid
)
select users.id, users.username,
    (
        select array_agg(userroles.roleid::text)
        from userroles
        join roles_universe on roles_universe.roleid=userroles.roleid
        where userroles.userid=users.id
    ) as roles
from users
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
    results.key_labels += "Users for Role(s)"
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_user.surrogate(),
            username=api.cgen.yenot_user.name(
                url_key="id", represents=True, skip_write=True
            ),
            roles=api.cgen.matrix(),
        )

        p = {"roles": roles}
        results.tables["users", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["roles:universe"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/userroles/by-roles", name="put_api_userroles_by_roles")
def put_api_userroles_by_roles(request):
    users = api.table_from_tab2("users", required=["id", "roles"], matrix=["roles"])
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.update_rows("users", users, matrix={"roles": "userroles"})
        conn.commit()

    return api.Results().json_out()


@app.get("/api/roleactivities/by-roles", name="get_api_roleactivities_by_roles")
def get_api_roleactivities_by_roles(request):
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
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
    results.key_labels += "Activities for Role(s)"
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_activity.surrogate(),
            act_name=api.cgen.yenot_activity.name(
                label="Activity", url_key="id", represents=True
            ),
        )

        p = {"roles": roles}
        results.tables["activities", True] = api.sql_tab2(conn, select, p, cm)
        results.tables["rolenames"] = api.sql_tab2(conn, select2, p)
    return results.json_out()


@app.put("/api/roleactivities/by-roles", name="put_api_roleactivities_by_roles")
def put_api_roleactivities_by_roles(request):
    # Table roleactivities:
    # - id: activityid
    # - permissions: list of dictionaries with key roleid and associated metadata
    coll = api.table_from_tab2("roleactivities", required=["id", "permissions"])
    # comma delimited list of role ids
    roles = request.params.get("roles").split(",")
    roles = list(roles)

    update = """
-- update activity--role links for all roles in universe linked with some prior values.
with /*PERMISSIONS*/
, toupdate as (
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
with /*PERMISSIONS*/
, toinsert as (
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
        # TODO:  use upsert
        api.sql_void(conn, "set transaction isolation level serializable")

        for row in coll.rows:
            represented = [r["roleid"] for r in row.permissions]

            columns = ["roleid", "permitted", "dashboard", "dashprompts"]
            permlist = api.InboundTable([(c, None) for c in columns], [])
            for passed in row.permissions:
                if passed["roleid"] not in roles:
                    raise RuntimeError(
                        "roles parameter establishes universe of allowed values"
                    )
                permlist.rows.append(
                    permlist.DataRow(
                        passed["roleid"],
                        passed.get("permitted", False),
                        passed.get("dashboard", False),
                        passed.get("dashprompts", None),
                    )
                )

            # TODO: fix the ugly requirement for something to be in tolink param of delete:
            params = {
                "roles": roles,
                "tolink": tuple(represented)
                if len(represented) > 0
                else ("__bug_happens_here__",),
                "id": row.id,
            }

            # delete
            api.sql_void(conn, delete, params)
            if len(represented) > 0:
                ctypes = ["uuid", "boolean", "boolean", "json"]
                mogrifications = permlist.as_cte(
                    conn, "permissions", column_types=ctypes
                )

                # update
                my_update = update.replace("/*PERMISSIONS*/", mogrifications)
                api.sql_void(conn, my_update, params)
                # insert
                my_insert = insert.replace("/*PERMISSIONS*/", mogrifications)
                api.sql_void(conn, my_insert, params)

        conn.commit()

    return api.Results().json_out()
