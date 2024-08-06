from thefuzz import fuzz, process
from flask import request, Blueprint, g
from lib.drivejwt import DriveJwt
from lib.secretsmanager import SecretManager
from lib.validations import Validations
from lib.constants import *
import datetime
VALIDATIONS = Validations()
bp = Blueprint('name_match', __name__)

import logging
from pythonjsonlogger import jsonlogger

# Setup logging
current_date = datetime.datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

@bp.before_request
def validate_user():
    """
        Jwt Authentication
    """
    request_data = {
            'time_start': datetime.datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
    request.logger_data = request_data
    
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls:
            return

        jwtlib = DriveJwt(request, CONFIG)

        jwtres, status_code = jwtlib.jwt_login()

        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
        else:
            return jwtres, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route('/v1', methods=['POST'])
def v1():
    try:
        res, status_code = VALIDATIONS.verify_name(request)
        if status_code == 400:
            return res, status_code
        name = res['name']
        original_name = res['original_name']

        ratio = fuzz.ratio(name, original_name)
        token_set_ratio = fuzz.token_set_ratio(name, original_name)
        token_sort_ratio = fuzz.token_sort_ratio(name, original_name)

        if ratio >= token_set_ratio and ratio >= token_sort_ratio:
            match = ratio
        elif token_set_ratio >= ratio and token_set_ratio >= token_sort_ratio:
            match = token_set_ratio
        elif token_sort_ratio >= ratio and token_sort_ratio >= token_set_ratio:
            match = token_sort_ratio
        else:
            match = 0
        if match > 70:
            return {STATUS: SUCCESS, "match": match}, 200
        else:
            return {STATUS: ERROR, "match": match}, 200
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "v1: " + str(e)}, 401

@bp.route('/v2', methods=['POST'])
def v2():
    try:
        res, status_code = VALIDATIONS.verify_name(request)
        if status_code == 400:
            return res, status_code
        name = res['name']
        original_name = res['original_name']
        
        res = process.extract(name, [original_name])
        return {STATUS: SUCCESS, "match": res}, 200
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "v2: " + str(e)}, 401

def name_match_v3(name, original_name):
    try:
        res, status_code = VALIDATIONS.verify_name_v3(name, original_name)
        if status_code == 400:
            return res
        
        name = res['name']
        original_name = res['original_name']
        
        ratio = fuzz.ratio(name, original_name)
        token_set_ratio = fuzz.token_set_ratio(name, original_name)
        token_sort_ratio = fuzz.token_sort_ratio(name, original_name)

        if ratio >= token_set_ratio and ratio >= token_sort_ratio:
            match = ratio
        elif token_set_ratio >= ratio and token_set_ratio >= token_sort_ratio:
            match = token_set_ratio
        elif token_sort_ratio >= ratio and token_sort_ratio >= token_set_ratio:
            match = token_sort_ratio
        else:
            match = 0

        if match > 70:
            return {STATUS: SUCCESS, "match": match}
        else:
            return {STATUS: ERROR, "match": match}

    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "v2: " + str(e)}

@bp.after_request
def after_request(response):
    try:
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
        
        
        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'time_end': datetime.datetime.utcnow().isoformat()
        }
        log_data = {
            'request': request.logger_data,
            'response': response_data
        }
        logger.info(log_data)
        return response
    except Exception as e:
        print(f"Logging error: {str(e)}")
    return response

@bp.errorhandler(Exception)
def handle_exception(e):
    log_data = {
        'error': str(e),
        'time': datetime.datetime.utcnow().isoformat()
    }
    logger.error(log_data)
    response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
    response.status_code = 500
    return response
