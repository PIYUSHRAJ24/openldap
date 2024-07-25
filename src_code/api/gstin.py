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
    gstin = request.form.get("gstin")
    org_id = request.form.get("org_id")

    if not gstin:
        return jsonify({"status": "error", "response": "GSTIN number not provided"}), 400

    if not org_id:
        return jsonify({"status": "error", "response": "Organization ID not provided"}), 400

    if not is_valid_gstin(gstin):
        return jsonify({"status": "error", "response": "Please enter a valid GSTIN number, pattern not match"}), 400

    # Check if org_id exists
    query = {"org_id": org_id}
    fields = {}
    res, status_code = MONGOLIB.org_eve("org_details", query, fields, limit=1)

    if status_code != 200:
        return jsonify({"status": "error", "response": res}), status_code
    
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "gstin": gstin,
        "updated_on": date_time,
    }

    try:
        # Update org_id if it exists
        res, status_code = MONGOLIB.org_eve_update("org_details", data, org_id)
    except Exception as e:
        return jsonify({"status": "error", "error_description": "Technical error", "response": str(e)}), 400

    if status_code != 200:
        return jsonify({"status": "error", "response": res}), status_code

    RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_details_update_")
    return jsonify({"status": "success", "response": "GSTIN number set successfully"}), 200

def is_valid_gstin(gstin):
    gstin_pattern = re.compile(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$')
    return bool(gstin_pattern.match(gstin))
