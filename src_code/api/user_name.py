import hashlib
import random
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

# Initialize libraries
MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()
accounts_eve = CONFIG["accounts_eve"]
# Configuration and blueprint setup
logs_queue = "org_logs_PROD"
bp = Blueprint("search", __name__)
logarray = {}
CONFIG = dict(CONFIG)
data_vault = CONFIG["data_vault"]
secrets = json.loads(SecretManager.get_secret())


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


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return jsonify({STATUS: SUCCESS})

@bp.route("/retrieve_name", methods=["POST"])
def retrieve_name():
    try:
        aadhar = request.form.get("uid")
        mobile_no = request.form.get("mobile")
        email = request.form.get("username")

        if not aadhar and not mobile_no and not email:
            return {
                "status": "error",
                "response": "Please enter a valid mobile number or aadhar number or email",
            }, 400
        
        digilockerid_aadhar = None
        digilockerid_mobile = None
        digilockerid_email = None
        name = None
        
        # Aadhaar validation and processing
        if aadhar:
            # adh = CommonLib.aes_decryption_v2(aadhar, g.org_id[:16])
            if aadhar and not re.match(r"^\d{12}$", aadhar):
                return {"status": "error", "response": "Invalid Aadhaar number"}, 400

            token = get_token(aadhar)
            if not token or len(token) != 36:
                return {
                    "status": "error",
                    "response": "We were unable to find any DigiLocker Account linked with this Aadhaar Number.",
                }, 400

            where = {"vt": token}
            if os.getenv('ENVIRONMENT') == "BETA":
                resp, code = MONGOLIB.accounts_eve_v1('users', where, {'uid_token': 1})
                if code != 200:
                    return {
                        "status": "error",
                        "response": "We were unable to find any DigiLocker Account for this Aadhaar Number.",
                    }, 400
                where = {"uid_token": urllib.parse.quote(resp["data"][0]['uid_token'])}

            resp, code = MONGOLIB.accounts_eve_v2('users', where, {'digilockerid': 1})
            if code == 200:
                digilockerid_aadhar = resp["data"][0].get('digilockerid')

        # Mobile number validation and processing
        if mobile_no:
            if not re.match(r"^\d{10}$", mobile_no):
                return {"status": "error", "response": "Invalid mobile number"}, 400

            query = {"mobile_no": mobile_no}
            resp, status_code = MONGOLIB.accounts_eve(accounts_eve['collection_usr'], query, {"digilockerid": 1}, limit=1)
            if status_code == 200 and resp["status"] == "success":
                user_info = resp["response"][0]
                digilockerid_mobile = user_info.get("digilockerid")

        # Email validation and processing
        if email:
            if not re.match(r"^[a-zA-Z0-9 \.\-\_\@]*$", email):
                return {"status": "error", "response": "Invalid username"}, 400

            query = {"user_alias": email}
            resp, status_code = MONGOLIB.accounts_eve(accounts_eve['collection_usr'], query, {"digilockerid": 1}, limit=1)
            if status_code == 200 and resp["status"] == "success":
                user_info = resp["response"][0]
                digilockerid_email = user_info.get("digilockerid")
        digilockerids = set(filter(None, [digilockerid_aadhar, digilockerid_mobile, digilockerid_email]))
        if len(digilockerids) > 1:
            return {
                "status": "error",
                "response": "Mismatch between digilockerid for Aadhaar, mobile number, and username.",
            }, 400
        
        if digilockerids:
            digilockerid = digilockerids.pop()
            name = CommonLib.get_profile_details(digilockerid).get('username', '')

        # Get the name from digilockerid
        if digilockerid:
            name = CommonLib.get_profile_details(digilockerid).get('username', '')

            return {
                "status": "success",
                "digilockerid": digilockerid,
                "name": name
            }, 200
        else:
            return {
                "status": "error",
                "response": "No user found with the provided information.",
            }, 400

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {
            "status": "error",
            "response": Errors.error('err_1201')+"[#1701]",
        }, 400

def get_token(adh):
        ''' get token '''
        url = data_vault['url']+'/gettoken'
        payload = 'payload_id='+adh
        headers = {
            'clientid': data_vault['clientid'],
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        try:
            response = requests.request("POST", url, headers=headers, data=payload, timeout=20)
            if response.status_code != 200:
                return False
            res = json.loads(response.text)
            if len(str(res.get('token', ''))) == 36:
                return res['token']
            else:
                return response.text
        except Exception as e:
            VALIDATIONS.log_exception(e)
            print(e)
            return Errors.error('err_1201')+"[#1702]"
        return ""

@bp.route("/user", methods=["POST"])
def user():
    try:
        # Get the user data from the form or JSON payload
        aadhar = request.form.get("uid")
        mobile_no = request.form.get("mobile")
        email = request.form.get("username")

        # Prepare API URL and payload
        url = CONFIG["acsapi"]['url'] + '/retrieve_account/1.0'
        ts = str(int(time.time()))
        client_id = CONFIG["acsapi"]['client_id']
        client_secret = CONFIG["acsapi"]["client_secret"]
        key = client_secret + client_id + ts
        hash_object = hashlib.sha256(key.encode())
        hmac = hash_object.hexdigest()
        payload = {
            "mobile": mobile_no or '',
            "username": email or '',
            "uid": aadhar or '',
            "clientid": client_id,
            "hmac": hmac,
            "ts": ts
        }
        print(payload)
        # Prepare headers with HMAC authentication
        headers = {
            'Content-Type': "application/x-www-form-urlencoded"
        }
        # Make the API request
        response = requests.post(url, headers=headers, data=payload, timeout=20)
        if response.status_code != 200:
            return json.loads(response.text), response.status_code 

        # Return the JSON response from the API
        return response.json()

    except Exception as e:
        # Catch and return any errors
        VALIDATIONS.log_exception(e)
        return {"status": "error", "response": Errors.error('err_1201')+"[#1703]"}, 400