from bottle import request, response
import yenot.backend.api as api
import yenotauth.core

app = api.get_global_app()


@app.get("/api/user/<userid>/reports", name="api_user_reports")
def get_user_reports(userid):
    global app
    dashboard = api.parse_bool(request.params.get("dashboard", False))

    select = """
select activities.act_name, roles.role_name as role, roles.sort as role_sort, 
    activities.description as description, 
    activities.url, activities.note, activities.id
from userroles
join roleactivities on roleactivities.roleid=userroles.roleid
join roles on roles.id=userroles.roleid
join activities on activities.id=roleactivities.activityid
where roleactivities.permitted /*WHERE*/"""

    results = api.Results()
    with app.dbconn() as conn:
        params = {}
        wheres = []
        if userid == "logged-in":
            wheres.append(
                "userroles.userid = (select userid from sessions where sessions.id=%(sid)s)"
            )
            params["sid"] = request.headers["X-Yenot-SessionID"]
        else:
            wheres.append("userroles.userid = %(uid)s")
            params["uid"] = userid
        if dashboard:
            wheres.append("roleactivities.dashboard")

        if len(wheres) > 0:
            select = select.replace("/*WHERE*/", " and " + " and ".join(wheres))

        data = api.sql_tab2(conn, select, params)

        reports = {r.name: r for r in app.report_endpoints()}
        data = data[0], [r for r in data[1] if r.act_name in reports]

        columns = api.tab2_columns_transform(data[0], insert=[("id", "prompts")])

        def xform_add_prompts(oldrow, row):
            row.prompts = yenotauth.core.route_prompts(reports[row.act_name])

        rows = api.tab2_rows_transform(data, columns, xform_add_prompts)

        results.tables["reports", True] = columns, rows
    return results.json_out()
