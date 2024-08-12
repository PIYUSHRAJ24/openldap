import hashlib
import random
import uuid
import bcrypt
import requests
import time
import os
import re
import json
from datetime import datetime, timezone
from flask import request, Blueprint, g, jsonify
from lib.constants import *
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.validations import Validations
from api.org_activity import activity_insert
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash


import logging
from pythonjsonlogger import jsonlogger

# Setup logging
current_date = datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()

# Configuration and blueprint setup
logs_queue = 'org_logs_PROD'
bp = Blueprint("udyam", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())

try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local

@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    request_data = {
            'time_start': datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
    request.logger_data = request_data
    
    logarray.update({
        ENDPOINT: request.path,
        HEADER: {
            'user-agent': request.headers.get('User-Agent'),
            "clientid": request.headers.get("clientid"),
            "ts": request.headers.get("ts"),
            "orgid": request.headers.get("orgid"),
            "hmac": request.headers.get("hmac")
        },
        REQUEST: {}
    })
    g.org_id = request.headers.get("orgid")
    
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

        res, status_code = VALIDATIONS.hmac_authentication(request)

        if status_code != 200:
            return res, status_code

    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 401
    

@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return jsonify({STATUS: SUCCESS})

@bp.route("/update_udyam", methods=["POST"])
def set_udyam():
    res, status_code = VALIDATIONS.is_valid_udyam_v2(request, g.org_id)

    udyam_no = res.get('udyam_number')
    mobile = res.get('mobile')
    
    if not udyam_no:
        return jsonify({"status": "error", "response": "UDYAM number not provided"}), 400
    
    if not mobile:
        return jsonify({"status": "error", "response": "UDYAM name not provided"}), 400

    if not g.org_id:
        return jsonify({"status": "error", "response": "Organization ID not provided"}), 400

    res = ids_udyam_verify(udyam_no, mobile)
    status_code = res[1]
    if status_code != 200 :
        log_data = {RESPONSE: res}
        logarray.update(log_data)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
        return jsonify({"status": "error", "response": "UDYAM number not verified"}), 400
        
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "udyam": udyam_no,
        "updated_on": date_time,
    }
    try:
        RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_details_update_")
        log_data = {RESPONSE: "UDYAM number set successfully"}
        logarray.update(log_data)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
        return jsonify({"status": "success", "response": "UDYAM number set successfully"}), 200
    except Exception as e:
        log_data = {RESPONSE: e}
        logarray.update(log_data)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
        return jsonify({"status": "error", "error_description": "Technical error", "response": str(e)}), 400


def ids_udyam_verify(udyam_no, mobile):
    try:
        ids_api_url = CONFIG["ids"]["url"]
        curlurl=f"{ids_api_url}gateway/1.0/verify_udcer"
        ids_clientid = CONFIG["ids"]["client_id"]
        ids_clientsecret = CONFIG["ids"]["client_secret"]
        if not udyam_no or not mobile:
            log_data = {RESPONSE: 'UDYAM number or name not provided'}
            logarray.update(log_data)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
            return {"status": "error", "error_desc": "err_112"}, 400
     
        data = {
            "mobile": mobile,
            "udyam_number": udyam_no
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
                
        curl_result = requests.post(curlurl, headers=headers, data=fields,timeout=5)
       
        response = curl_result.json()
      
        log = {'url': curlurl, 'req': fields, 'res': response, 'head': headers}
        logarray.update(log)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
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
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'entity_auth_logs_')
        return {"status": "error", 'response': str(e)}, 500

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
            'time_end': datetime.utcnow().isoformat()
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
        'time': datetime.utcnow().isoformat()
    }
    logger.error(log_data)
    response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
    response.status_code = 500
    return response