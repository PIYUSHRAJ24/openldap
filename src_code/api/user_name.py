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

try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local


@bp.before_request
def validate_user():
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
        consent_bypass_urls = ('user')
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
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#1900]"}, 401


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
        adh = None
        mobile = None
        user_name = None
        # Get the user data from the form or JSON payload
        aadhar = request.form.get("uid")
        mobile_no = request.form.get("mobile")
        email = request.form.get("username")
        if aadhar:
            adh = CommonLib.aes_decryption_v2(aadhar, g.org_id[:16])
        elif mobile_no:
            mobile = CommonLib.aes_decryption_v2(mobile_no, g.org_id[:16])
        elif email:
            user_name = CommonLib.aes_decryption_v2(email, g.org_id[:16])
        else:
            return {"status": "error", "response": "Please enter a valid mobile number or aadhar number or email"}, 400
        # Prepare API URL and payload
        url = CONFIG["acsapi_dl"]['url'] + '/retrieve_account/1.0'
        ts = str(int(time.time()))
        client_id = CONFIG["acsapi_dl"]['client_id']
        client_secret = CONFIG["acsapi_dl"]["client_secret"]
        key = client_secret + client_id + ts
        hash_object = hashlib.sha256(key.encode())
        hmac = hash_object.hexdigest()
        payload = {
            "mobile": mobile or '',
            "username": user_name or '',
            "uid": adh or '',
            "clientid": client_id,
            "hmac": hmac,
            "ts": ts
        }
        # Prepare headers with HMAC authentication
        headers = {
            'Content-Type': "application/x-www-form-urlencoded"
        }
        # Make the API request
        response = requests.post(url, headers=headers, data=payload, timeout=20)
        if response.status_code != 200:
            return json.loads(response.text), response.status_code 
        
        response_data = response.json()
        status = response_data.get("status")
        data = json.dumps(response_data.get("data"))
        encrypted_data = CommonLib.aes_encryption(data, g.org_id[:16])
        encrypted_response = {
            "status": status,
            "data": encrypted_data
        }
        return encrypted_response

    except Exception as e:
        # Catch and return any errors
        VALIDATIONS.log_exception(e)
        return {"status": "error", "response": Errors.error('err_1201')+"[#1703]"}, 400