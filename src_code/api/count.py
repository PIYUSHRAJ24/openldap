from flask import request, Blueprint

from lib.constants import *
from lib.elasticlib import ElasticLib

# ELASTICLIB = ElasticLib()
bp = Blueprint('count', __name__)
logarray = {}


@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    logarray.update({
        ENDPOINT: request.path,
        HEADER: {
            'user-agent': request.headers.get('User-Agent'),
            "client_id": request.headers.get("client_id"),
            "ts": request.headers.get("ts"),
            "hmac": request.headers.get("hmac")
        },
        REQUEST: {}
    })
    if dict(request.args):
        logarray[REQUEST].update(dict(request.args))
    if dict(request.values):
        logarray[REQUEST].update(dict(request.values))
    if request.headers.get('Content-Type') == "application/json":
        logarray[REQUEST].update(dict(request.json)) # type: ignore
    
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls:
            return

    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error("err_1201")+"[#1300]"}, 401


@bp.route('/orgcount', methods=['GET', 'POST'])
def orgcount():
    return ELASTICLIB.entity_count()