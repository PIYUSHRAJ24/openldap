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

# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()

# Configuration and blueprint setup
logs_queue = "org_details_update_"
bp = Blueprint("gstin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())

# GSTIN validation pattern
gstin_pattern = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'

try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local

@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
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

@bp.route("/set_gstin", methods=["POST"])
def set_gstin():
    res, status_code = VALIDATIONS.is_valid_gstin_v2(request, g.org_id)
    gstin_no = res.get('gstin')
    gstin_name = res.get('name')
    
    if not gstin_no:
        return jsonify({"status": "error", "response": "GSTIN number not provided"}), 400
    
    if not gstin_name:
        return jsonify({"status": "error", "response": "GSTIN name not provided"}), 400

    if not g.org_id:
        return jsonify({"status": "error", "response": "Organization ID not provided"}), 400

    res = ids_gstin_verify(gstin_no, gstin_name)
    
    status_code = res[1]

    if status_code != 200 :
        return jsonify({"status": "error", "response": "GSTIN number not verified"}), 400
        
    # Check if org_id exists
    query = {"gstin": gstin_no}
    fields = {}
    res = MONGOLIB.org_eve("org_details", query, fields, limit=1)
    status_code = res[1]
    if status_code == 200:
        return jsonify({"status": "success", "response": 'GSTIN is already associated with the organization.'}), status_code
    
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "gstin": gstin_no,
        "updated_on": date_time,
    }
    try:
        RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_details_update_")
        return jsonify({"status": "success", "response": "GSTIN number set successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "error_description": "Technical error", "response": str(e)}), 400


def ids_gstin_verify(gstin_no, gstin_name):
    try:
        ids_api_url = CONFIG["ids"]["url"]
        curlurl = f"{ids_api_url}gateway/1.0/verify_gstin"
        ids_clientid = CONFIG["ids"]["client_id"]
        ids_clientsecret = CONFIG["ids"]["client_secret"]
        if not gstin_no or not gstin_name:
            return {"status": "error", "error_desc": "err_112"}, 400
     
        data = {
            "GSTIN": gstin_no,
            "FullName": gstin_name
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
