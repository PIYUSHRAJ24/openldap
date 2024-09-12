import hashlib
import random
import traceback
import uuid
import bcrypt
import requests
import time
import os, re, urllib.parse, json
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
from lib.rabbitmqlogs import RabbitMQLogs
# import inspect
import logging
from pythonjsonlogger import jsonlogger

# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()
accounts_eve = CONFIG["accounts_eve"]
# Configuration and blueprint setup
logs_queue = "org_logs_PROD"
bp = Blueprint("user_name", __name__)
logarray = {}
CONFIG = dict(CONFIG)
data_vault = CONFIG["data_vault"]
secrets = json.loads(SecretManager.get_secret())

current_date = datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-AUTH-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)


@bp.before_request
def validate_user():
    """
    HMAC Authentication
    """
    request_data = {
        "time_start": datetime.utcnow().isoformat(),
        "method": request.method,
        "url": request.url,
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True),
    }
    request.logger_data = request_data

    logarray.update(
        {
            ENDPOINT: request.path,
            HEADER: {
                "user-agent": request.headers.get("User-Agent"),
                "clientid": request.headers.get("clientid"),
                "ts": request.headers.get("ts"),
                "hmac": request.headers.get("hmac"),
            },
            REQUEST: {},
        }
    )
    

    if dict(request.args):
        logarray[REQUEST].update(dict(request.args))
    if dict(request.values):
        logarray[REQUEST].update(dict(request.values))
    if request.headers.get("Content-Type") == "application/json":
        logarray[REQUEST].update(dict(request.json))  # type: ignore

    try:
        if request.method == "OPTIONS":
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = "healthcheck"
        if request.path.split("/")[1] in bypass_urls:
            return

        res, status_code = VALIDATIONS.hmac_authentication(request)
        if status_code != 200:
            return res, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return jsonify({STATUS: SUCCESS})

@bp.route("/usr_name", methods=["POST"])
def usr_name():
    try:
        # Get the user data from the form or JSON payload
        aadhar = request.form.get("uid")
        mobile_no = request.form.get("mobile")
        email = request.form.get("username")

        # If all fields are missing, return an error
        if not aadhar and not mobile_no and not email:
            return {
                "status": "error",
                "response": "Please enter a valid mobile number, Aadhaar number, or email",
            }, 400

        # Aadhaar decryption and validation
        if aadhar:
            if aadhar and not re.match(r"^\d{12}$", aadhar):
                return {"status": "error", "response": "Invalid Aadhaar number"}, 400

        # Prepare API URL and payload
        url = CONFIG["acsapi"]['url'] + '/retrieve_account/1.0'
        ts = str(int(time.time()))
        client_id = CONFIG["acsapi"]['client_id']
        client_secret = CONFIG["acsapi"]["client_secret"]
        key = client_secret + client_id + ts
        hash_object = hashlib.sha256(key.encode())
        hmac = hash_object.hexdigest()
        payload = {
            "mobile": mobile_no,
            "username": email,
            "uid": aadhar,
            "clientid": client_id,
            "hmac": hmac,
            "ts": ts
        }
        # Prepare headers with HMAC authentication
        headers = {
            'client-id': client_id,
            'ts': ts,
            'hmac': hmac
        }
        # Make the API request
        response = requests.post(url, headers=headers, params=payload, timeout=20)
        print(json.loads(response.text))
        if response.status_code != 200:
            return {"status": "error", "response": "Failed to retrieve account"}, response.status_code

        # Return the JSON response from the API
        return response.json()

    except Exception as e:
        VALIDATIONS.log_exception(e)
        # Catch and return any errors
        return {"status": "error", "response": "Some technical error occurred. Please try again after sometime."}, 400