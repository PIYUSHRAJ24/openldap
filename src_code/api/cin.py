import hashlib
import random
import uuid
import bcrypt
import requests
import time
import os
import re
import json
import logging
from datetime import datetime, timezone
from flask import request, Blueprint, g, jsonify
from lib.constants import *
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.validations import Validations
from api.org_activity import activity_insert
from api.org import esign_consent_get
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()

# Configuration and blueprint setup
logs_queue = "org_details_update_"
bp = Blueprint("cin", __name__)
logger = logging.getLogger(__name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())

# cin validation pattern
cin_pattern = r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$"

try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local


@bp.before_request
def validate():
    """
        JWT Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}

        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.path
        if request.path.split('/')[-1] == "get_user_request":
            res, status_code = CommonLib().validation_rules(request, True)
            if status_code != 200:
                return res, status_code
            logarray.update({ENDPOINT: g.endpoint, REQUEST: {'user': res[0], 'client_id': res[1]}})
            return
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_login()
        if status_code != 200:
            return jwtres, status_code
        g.path = jwtres
        g.jwt_token = jwtlib.jwt_token
        g.did = jwtlib.device_security_id
        g.digilockerid = jwtlib.digilockerid
        g.org_id = jwtlib.org_id
        g.role = jwtlib.user_role
        g.org_access_rules = jwtlib.org_access_rules
        g.org_user_details = jwtlib.org_user_details
        g.consent_time = ''
        consent_bypass_urls = ('update_cin')
        if request.path.split('/')[1] not in consent_bypass_urls and request.path.split('/')[-1] not in consent_bypass_urls:
            consent_status, consent_code = esign_consent_get()
            if consent_code != 200 or consent_status.get(STATUS) != SUCCESS or not consent_status.get('consent_time'):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            try:
                datetime.strptime(consent_status.get('consent_time', ''), D_FORMAT)
            except Exception:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            g.consent_time = consent_status.get('consent_time')

        logarray.update({'org_id': g.org_id, 'digilockerid': g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return jsonify({STATUS: SUCCESS})

@bp.route("/update_cin", methods=["POST"])
def update_cin():
    res, status_code = VALIDATIONS.is_valid_cin_v2(request, g.org_id)
    cin_no = res.get('cin')
    cin_name = res.get('name')
    if not cin_no:
        return jsonify({"status": "error", "response": "CIN number not provided"}), 400
    
    if not cin_name:
        return jsonify({"status": "error", "response": "CIN name not provided"}), 400

    if not g.org_id:
        return jsonify({"status": "error", "response": "Organization ID not provided"}), 400

    res = ids_cin_verify(cin_no, cin_name)

    status_code = res[1]

    if status_code != 200 :
        return jsonify({"status": "error", "response": "CIN number not verified"}), 400
    
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "cin": cin_no,
        "updated_on": date_time,
    }
    try:
        RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_details_update_")
        return jsonify({"status": "success", "response": "CIN number set successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "error_description": "Technical error", "response": str(e)}), 400


def ids_cin_verify(cin_no, cin_name):
    try:
        ids_api_url = CONFIG["ids"]["url"]
        curlurl = f"{ids_api_url}gateway/1.0/verify_cin"
        ids_clientid = CONFIG["ids"]["client_id"]
        ids_clientsecret = CONFIG["ids"]["client_secret"]
        if not cin_no or not cin_name:
            return {"status": "error", "error_desc": "err_112"}, 400
     
        data = {
            "cin": cin_no,
            "name": cin_name
        }
        fields = json.dumps(data)

        ts = str(int(time.time()))
        key = f"{ids_clientsecret}{ids_clientid}{g.org_id}{ts}"
        hmac = hashlib.sha256(key.encode()).hexdigest()
        
        headers = {
            'ts': ts,
            'clientid': ids_clientid,
            'hmac': hmac,
            'orgid': g.org_id,
            'Content-Type': 'application/json'
        }
        curl_result = requests.post(curlurl, headers=headers, data=fields, timeout=5)
        response = curl_result.json()
        log = {'url': curlurl, 'req': fields, 'res': response, 'head': headers}
        logarray.update(log)
        
        code = curl_result.status_code
        if code == 200 and response.get('status') == 'success':
            return {'status': 'success', 'response': response['msg']}, code
        elif 400 <= code <= 499 or code == 503:
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'entity_auth_logs_')
            return {'status': 'error', 'response': response['msg']}, code
        else:
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'entity_auth_logs_')
            return {"status": "error", "error_desc": f"Technical error occurred. Code: {code}"}, code
    
    except Exception as e:
        logarray.update({"error": str(e)})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'entity_auth_logs_')
        return {"status": "error", 'response': str(e)}, 500

# @bp.after_request
# def after_request(response):
#     try:
#         response.headers['Content-Security-Policy'] = "default-src 'self'"
#         response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
#         response.headers['X-Content-Type-Options'] = 'nosniff'
#         response.headers['X-Frame-Options'] = 'SAMEORIGIN'
#         response.headers['X-XSS-Protection'] = '1; mode=block'
#         response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
#         response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
#         response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
        
        
#         response_data = {
#             'status': response.status,
#             'headers': dict(response.headers),
#             'body': response.get_data(as_text=True),
#             'time_end': datetime.utcnow().isoformat()
#         }
#         log_data = {
#             'request': request.logger_data,
#             'response': response_data
#         }
#         logger.info(log_data)
#         return response
#     except Exception as e:
#         print(f"Logging error: {str(e)}")
#     return response

# @bp.errorhandler(Exception)
# def handle_exception(e):
#     log_data = {
#         'error': str(e),
#         'time': datetime.utcnow().isoformat()
#     }
#     logger.error(log_data)
#     response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
#     response.status_code = 500
#     return response