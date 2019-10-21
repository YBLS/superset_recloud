""" custom functools """
import logging
import functools
import requests
import json

from flask import (
    request,
    g,
    session
)

from superset import (
    app
)

def transform_sql(f):
    def wraps(self, *args, ** kwargs):
        sql = request.form.get('sql')
        _sql = handleSqlTransform(sql)
        parameter = request.form.to_dict()
        parameter['sql'] = _sql
        request.form = parameter
        return f(self, *args, **kwargs)   
    return functools.update_wrapper(wraps, f)

def handleSqlTransform(sql):
    transform_url = app.config.get("CUSTOM_DECORATOR_SQLTRANSFORM_URL")
    if not transform_url:
        return sql

    body = {'sql' : sql}
    access_token = session.get('oauth')[0]
    header = {'content-type':'application/json','Authorization':'bearer {0}'.format(access_token)}
    response = requests.post(transform_url, data = json.dumps(body), headers = header)
    if response.status_code == 200:
        data = json.loads(response.text)
        if data['ErrorCode'] == 0:
            return data['Data']['sql']
        else:
            pass
    elif response.status_code == 401:
        pass
    else:
        raise(response.text)
