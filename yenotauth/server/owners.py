import uuid
import yenot.backend.api as api

app = api.get_global_app()


def owner_sidebar(idcolumn):
    return [{"name": "owner_general", "on_highlight_row": {"id": idcolumn}}]


@app.get(
    "/api/owners/list",
    name="get_api_owners_list",
    report_title="Owner List",
    report_sidebars=owner_sidebar("id"),
)
def get_api_owners_list():
    select = """
select owners.id, owners.owner_name, userowners2.count
from owners
left outer join (
                    select ownerid, count(*)
                    from userowners 
                    join users on users.id=userowners.userid
                    group by ownerid) as userowners2 on userowners2.ownerid=owners.id
"""

    results = api.Results(default_title=True)
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_owner.surrogate(),
            owner_name=api.cgen.yenot_owner.name(
                label="Owner", url_key="id", represents=True
            ),
            count=api.cgen.auto(label="Users", skip_write=True),
        )
        results.tables["owners", True] = api.sql_tab2(conn, select, None, cm)
    return results.json_out()


@app.get("/api/owner/new", name="get_api_owner_new")
def get_api_owner_new():
    select = """
select owners.id, owners.owner_name
from owners
where false
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_owner.surrogate(),
            owner_name=api.cgen.yenot_owner.name(
                label="Owner", url_key="id", represents=True
            ),
        )
        cols, rows = api.sql_tab2(conn, select, None, cm)

        def default_row(index, row):
            row.id = str(uuid.uuid1())

        rows = api.tab2_rows_default(cols, [None], default_row)
        results.tables["owner", True] = cols, rows
    return results.json_out()


@app.get("/api/owner/<ownerid>", name="get_api_owner_record")
def get_api_owner_record(ownerid):
    select = """
select owners.id, owners.owner_name
from owners
where owners.id=%(r)s
"""

    results = api.Results()
    with app.dbconn() as conn:
        cm = api.ColumnMap(
            id=api.cgen.yenot_owner.surrogate(),
            owner_name=api.cgen.yenot_owner.name(
                label="Owner", url_key="id", represents=True
            ),
        )

        results.tables["owner", True] = api.sql_tab2(conn, select, {"r": ownerid}, cm)
    return results.json_out()


@app.put("/api/owner/<ownerid>", name="put_api_owner_record")
def put_api_owner_record(ownerid):
    owner = api.table_from_tab2("owner", amendments=["id"], required=["owner_name"])

    if len(owner.rows) != 1:
        raise api.UserError("invalid-input", "Exactly one owner required.")

    for row in owner.rows:
        if not hasattr(row, "id"):
            row.id = ownerid

    with app.dbconn() as conn:
        with api.writeblock(conn) as w:
            w.upsert_rows("owners", owner)
        conn.commit()
    return api.Results().json_out()


@app.delete("/api/owner/<ownerid>", name="delete_api_owner_record")
def delete_api_owner_record(ownerid):
    # consider using cascade
    delete = """
delete from userowners where ownerid=%(r)s;
delete from owners where id=%(r)s;
"""

    with app.dbconn() as conn:
        api.sql_void(conn, delete, {"r": ownerid})
        conn.commit()
    return api.Results().json_out()
