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
bp = Blueprint("cin", __name__)
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

@bp.route("/set_cin", methods=["POST"])
def set_cin():
    
    res, status_code = VALIDATIONS.is_valid_cin_v3(request, g.org_id)
    return jsonify({"status": "error", "response": res}), status_code
    cin = res['cin']
    
    if not cin:
        return jsonify({"status": "error", "response": "CIN number not provided"}), 400

    if not g.org_id:
        return jsonify({"status": "error", "response": "Organization ID not provided"}), 400

    if not is_valid_cin(cin):
        return jsonify({"status": "error", "response": "Please enter a valid CIN number, pattern not match"}), 400

    # Check if org_id exists
    query = {"org_id": g.org_id}
    fields = {}
    res, status_code = MONGOLIB.org_eve("org_details", query, fields, limit=1)

    if status_code != 200:
        return jsonify({"status": "error", "response": res}), status_code
    
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "cin": cin,
        "updated_on": date_time,
    }

    try:
        # Update org_id if it exists
        res, status_code = MONGOLIB.org_eve_update("org_details", data, g.org_id)
    except Exception as e:
        return jsonify({"status": "error", "error_description": "Technical error", "response": str(e)}), 400

    if status_code != 200:
        return jsonify({"status": "error", "response": res}), status_code

    RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_details_update_")
    return jsonify({"status": "success", "response": "CIN number set successfully"}), 200

def is_valid_cin(cin):
    cin_pattern = re.compile(r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$")
    return bool(cin_pattern.match(cin))
