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
from lib.rabbitmqlogs import RabbitMQLogs
from lib.drivejwt import DriveJwt
from lib.validations import Validations
from api.org_activity import activity_insert
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager


# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()

accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']

# Configuration and blueprint setup
logs_queue = "org_details_update_"
bp = Blueprint("hmac_cin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())

# cin validation pattern
cin_pattern = r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$"

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
    head_load = logarray.get('HEADER',{})
    
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

@bp.route("/update_cin", methods=["POST"])
def update_cin():
    res, status_code = VALIDATIONS.is_valid_cin_v3(request, g.org_id)
    if res[STATUS] == ERROR:
        return jsonify({"status": "error", "response":res[ERROR_DES]}), status_code
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
    
    post_data = {
        "org_id":g.org_id,
        "cin": cin_no
        }
    try:
        RABBITMQ.send_to_queue({"data": post_data}, "Organization_Xchange", "org_update_details_")
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
            return jsonify({"status": "error", "response": "CIN details required"}), 400
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
