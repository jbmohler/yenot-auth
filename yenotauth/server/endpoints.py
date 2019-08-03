from bottle import request
import rtlib
import yenot.backend.api as api

app = api.get_global_app()

def report_endpoints(app):
    return [r for r in app.routes if 'report_title' in r.config and not r.config.get('hide_report', False)]

def route_prompts(r):
    return [] if 'report_prompts' not in r.config else r.config['report_prompts']()

def app_endpoints():
    kls_endpoint = rtlib.fixedrecord('Endpoint', ['method', 'url', 'name', 'description'])
    destinations = [r for r in app.routes]
    return [kls_endpoint(r.method, r.rule[1:], r.name, r.config.get('report_title', None)) for r in destinations if r.rule[1:] != '']

def get_api_endpoints_prompts():
    return api.PromptList(
            unregistered=api.cgen.boolean(label='Only Unregistered Endpoints'),
            __order__=['unregistered'])

@app.get('/api/endpoints', name='api_endpoints', \
        report_title='Yenot Entry Points', 
        report_prompts=get_api_endpoints_prompts)
def get_api_endpoints():
    unregistered = api.parse_bool(request.query.get('unregistered', False))

    cm = {}
    columns = [(a, cm.get(a, None)) for a in ['method', 'url', 'act_name', 'description']]
    destinations = [r for r in app.routes]
    rows = [(r.method, r.rule[1:], r.name, r.config.get('report_title', None)) for r in destinations if r.rule[1:] != '']

    results = api.Results(default_title=True)
    select = "select act_name from activities"
    with app.dbconn() as conn:
        _names = api.sql_rows(conn, select)
        names = {n.act_name for n in _names}

        unreg_rows = [r for r in rows if r[2] not in names]

    if unregistered:
        rows = unreg_rows

    x = rtlib.ClientTable(columns, rows)

    results.tables['endpoints', True] = x.as_tab2(column_map=cm)
    results.key_labels += '{} unregistered endpoints'.format(len(unreg_rows))
    results.keys['client-relateds'] = [('Register Endpoints', 'yenot:activities/register')]
    return results.json_out()
