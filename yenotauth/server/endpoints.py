import rtlib
import yenot.backend.api as api
import yenotauth.core

app = api.get_global_app()


def get_api_endpoints_prompts():
    return api.PromptList(
        unregistered=api.cgen.boolean(label="Only Unregistered Endpoints"),
        __order__=["unregistered"],
    )


@app.get(
    "/api/endpoints",
    name="api_endpoints",
    report_title="Yenot Entry Points",
    report_prompts=get_api_endpoints_prompts,
)
def get_api_endpoints(request):
    unregistered = api.parse_bool(request.query.get("unregistered", False))

    cm = api.ColumnMap(
        url=api.cgen.basic(label="URL"),
        act_name=api.cgen.auto(label="Activity Name"),
        description=api.cgen.auto(label="Title"),
    )
    columns = [
        (a, cm.get(a, None)) for a in ["method", "url", "act_name", "description"]
    ]
    destinations = [r for r in app.routes]
    rows = [
        (r.method, r.rule[1:], r.name, r.config.get("report_title", None))
        for r in destinations
        if r.rule[1:] != ""
    ]

    results = api.Results(default_title=True)
    select = "select act_name from activities"
    with app.dbconn() as conn:
        _names = api.sql_rows(conn, select)
        names = {n.act_name for n in _names}

        unreg_rows = [r for r in rows if r[2] not in names]

    if unregistered:
        rows = unreg_rows

    x = rtlib.ClientTable(columns, rows)

    results.tables["endpoints", True] = x.as_tab2(column_map=cm)
    results.key_labels += f"{len(unreg_rows)} unregistered endpoints"
    results.keys["client-relateds"] = [
        ("Register Endpoints", "yenot:activities/register")
    ]
    return results.json_out()


class ReportMetaXformer:
    def __init__(self, epname):
        self.routes = {
            r.name: r for r in app.routes if r.name == epname or epname == None
        }

    def xform(self, oldrow, row):
        route = self.routes.get(row.act_name, None)
        if route is None:
            return

        row.url = route.rule[1:]
        row.prompts = yenotauth.core.route_prompts(route)
        row.sidebars = yenotauth.core.route_sidebars(route)


@app.get("/api/report/<name>/runmeta", name="api_report_runmeta")
def api_report_runmeta(name):
    select = """
select 
    activities.act_name, activities.description, 
    activities.url, activities.note, activities.id
from activities
where name=%(n)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            url=api.cgen.basic(),
            prompts=api.cgen.__meta__(),
            id=api.cgen.yenot_report.surrogate(),
        )

        rawdata = api.sql_tab2(conn, select, {"n": name}, cm)

        if len(rawdata[1]) == 0:
            raise api.UserError(
                "invalid-param", "The report could not be found by this name."
            )

        xform = ReportMetaXformer(name)
        columns = api.tab2_columns_transform(
            rawdata[0], insert=[("url", "prompts", "sidebars")]
        )
        rows = api.tab2_rows_transform(rawdata, columns, xform.xform)

    results.tables["endpoint", True] = columns, rows
    return results.json_out()


@app.get("/api/report/<name>/info", name="api_report_info")
def api_report_info(name):
    select = """
select 
    id, act_name, description, url, 
    note --, technical
from activities
where act_name=%(n)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        rawdata = api.sql_tab2(conn, select, {"n": name})

        xform = ReportMetaXformer(name)
        columns = api.tab2_columns_transform(
            rawdata[0], insert=[("url", "method", "title", "prompts", "sidebars")]
        )

        def xform_squared(oldrow, row):
            if name in xform.routes:
                row.method = xform.routes[name].method
                if "report_title" in xform.routes[name].config:
                    row.title = xform.routes[name].config["report_title"]

            xform.xform(oldrow, row)

        rows = api.tab2_rows_transform(rawdata, columns, xform_squared)

        results.tables["endpoints", True] = columns, rows
    return results.json_out()
