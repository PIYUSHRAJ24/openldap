from requests import get
from flask import Blueprint, request, g
from datetime import datetime
from lib.constants import *
from lib.commonlib import CommonLib

bp = Blueprint('stats', __name__)

@bp.before_request
def default():
    try:
        g.logs_queue = 'acsapi_stats_logs_PROD'
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.endpoint.split('.')[-1]
        g.logs = {
            ENDPOINT: g.endpoint,
            'source': request.headers.get("Host"),
            'ip': request.remote_addr,
            'clientid': "",
            'browser': request.headers.get("User-Agent"),
            'timestamp': datetime.now().isoformat(),
            HEADERS: dict(request.headers),
            REQUEST: {**dict(request.values), **dict(request.args)}
        }
        res, status_code = CommonLib().validation_rules(request, True)
        if status_code != 200:
            return res, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_401'), RESPONSE: "JWT: " + str(e)}, 401

@bp.route('/statewise', methods=['GET'])
@bp.route('/statewise/<string:query>', methods=['GET'])
def get_statewise_count_by_date(query=None):
    try:
        try:
            query = datetime.strptime(query, "%d%m%Y") if query else None
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_204')}
        today = datetime.now()
        param = {'date': (query or today).strftime('%Y.%m.%d')}
        stats = get(CONFIG.get('dl_analytics', 'url')+CONFIG.get('dl_analytics', 'statewise')+'_v1', params=param).json()
        return {'date': (query or today).strftime('%d-%m-%Y'), 'stats': stats}
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: 'statewise: ' + str(e)}, 400

@bp.after_request
def after_request(response):
    code = response.status_code
    res = response.get_data(as_text=True)
    res_json = response.get_json()
    g.logs.update({RESPONSE_CODE: code})
    if not g.logs.get(RESPONSE):
        g.logs.update({
            RESPONSE: {STATUS: SUCCESS, 'content-length': len(res)} 
                if code == 200 and
                    (res_json.get('status') not in ('error', 'failed') if response.content_type == 'application/json' else True)
                else response.get_json() if response.content_type == 'application/json' else {STATUS: ERROR, 'content': res}
        })
    return response