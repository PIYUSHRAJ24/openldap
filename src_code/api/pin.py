import hashlib, random, uuid, bcrypt, requests, time, os, re
from datetime import datetime, timezone
from flask import request, Blueprint, g, render_template, jsonify
from lib.constants import *
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from api.org_activity import activity_insert
from api.org import esign_consent_get
from lib.validations import Validations
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()
VALIDATIONS = Validations()

logs_queue = "org_auth_update_"
bp = Blueprint("pin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
MIN_AGE = 0  # minimum age in years
MAX_AGE = 130  # maximum age in years
pin_pattern = r"^\d{6}$"

try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception as s:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local


@bp.before_request
def validate():
    """
    JWT Authentication
    """
    try:
        if request.method == "OPTIONS":
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = (
            "healthcheck",
            "get_count",
            "set_pin",
            "verify_pin",
            "verify_dob",
        )
        if (
            request.path.split("/")[1] in bypass_urls
            or request.path.split("/")[-1] in bypass_urls
        ):
            return
        org_bypass_urls = "create_org_user"
        g.endpoint = request.path
        if request.path.split("/")[-1] == "get_user_request":
            res, status_code = CommonLib().validation_rules(request, True)
            if status_code != 200:
                return res, status_code
            logarray.update(
                {ENDPOINT: g.endpoint, REQUEST: {"user": res[0], "client_id": res[1]}}
            )
            return

        jwtlib = DriveJwt(request, CONFIG)
        if request.path.split("/")[-1] in org_bypass_urls:
            jwtres, status_code = jwtlib.jwt_login()
        else:
            jwtres, status_code = jwtlib.jwt_login_org()
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
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
        g.consent_time = ""
        consent_bypass_urls = (
            "get_details",
            "get_access_rules",
            "get_users",
            "get_authorization_letter",
            "get_access_rules",
            "update_avatar",
            "get_avatar",
            "send_mobile_otp",
            "verify_mobile_otp",
            "send_email_otp",
            "verify_email_otp",
            "get_user_request",
            "get_user_requests",
            "update_cin_profile",
            "update_icai_profile",
            "update_udyam_profile",
            "esign_consent_get",
        )
        if (
            request.path.split("/")[1] not in consent_bypass_urls
            and request.path.split("/")[-1] not in consent_bypass_urls
        ):
            if CONFIG["esign_consent"]["esign_consent"] == "ON":
                consent_status, consent_code = esign_consent_get()
                if (
                    consent_code != 200
                    or consent_status.get(STATUS) != SUCCESS
                    or not consent_status.get("consent_time")
                ):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
                try:
                    datetime.strptime(
                        consent_status.get("consent_time", ""), D_FORMAT
                    )
                except Exception:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
                g.consent_time = consent_status.get("consent_time")

        logarray.update({"org_id": g.org_id, "digilockerid": g.digilockerid})
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error("err_1201")+"[#1400]"}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route("/set_pin", methods=["POST"])
def set_pin():

    pin = request.form.get("pin")
    org_id = request.form.get("org_id")
    digilockerid = request.form.get("digilockerid")

    pin_validate = re.match(pin_pattern, pin)
    if not pin_validate:
        return {
            "status": "error",
            "response": "Please enter valid PIN, pattern not match",
        }, 400

    if pin is None:
        return {"status": "error", "response": "PIN not provided"}, 400

    if org_id is None:
        return {"status": "error", "response": "Organization ID not provided"}, 400

    if digilockerid is None:
        return {"status": "error", "response": "DigiLocker ID not provided"}, 400

    password = pin.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password, salt)
    date_time = datetime.now().strftime(D_FORMAT)
    plain_txt = f"{org_id}{digilockerid}"
    auth_id = hashlib.sha256(plain_txt.encode()).hexdigest()
    data = {
        "auth_id": auth_id,
        "org_id": org_id,
        "digilockerid": digilockerid,
        "pin": hashed_password.decode("utf-8"),
        "created_on": date_time,
        "updated_on": date_time,
    }

    try:
        res, status_code = MONGOLIB.org_eve_post("org_auth", data)
    except Exception as e:
        VALIDATIONS.log_exception(e)
        if "duplicate key error" in str(e).lower():
            return {
                "status": "error",
                "error_description": "Duplicate entry",
                "response": str(e),
            }, 400
        else:
            return {
                "status": "error",
                "error_description": "Technical error",
                "response": str(e),
            }, 400

    if status_code != 200:
        logarray.update({"response": res})
       # RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, "pin/set_pin")
        return res, status_code

    pin_res = RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_auth_update_")
    logarray.update({"response": {"org_auth": res, "pin_update": pin_res}})
   # RABBITMQ_LOGSTASH.log_stash_logger(logarray, logs_queue, "reset_pin")
    return {"status": "success", "response": "PIN set successfully"}, 200


@bp.route("/verify_pin", methods=["POST"])
def verify_pin():
    org_id = request.form.get("org_id")
    digilockerid = request.form.get("digilockerid")
    provided_pin = request.form.get("pin")

    valid_pin = re.match(pin_pattern, provided_pin)
    if not valid_pin:
        return {
            "status": "error",
            "response": "Please enter valid PIN, pattern not match",
        }, 400

    if org_id is None:
        return {"status": "error", "response": "Organization ID not provided"}, 400

    if digilockerid is None:
        return {"status": "error", "response": "DigiLocker ID not provided"}, 400

    if provided_pin is None:
        return {"status": "error", "response": "PIN not provided"}, 400

    plain_txt = f"{org_id}{digilockerid}"
    auth_id = hashlib.sha256(plain_txt.encode()).hexdigest()
    query = {"auth_id": auth_id}
    fields = {"pin": 1}
    stored_pin_res, status_code = MONGOLIB.org_eve("org_auth", query, fields, limit=1)
    if status_code != 200:
        return stored_pin_res, status_code

    stored_pin_hash = get_pin_from_response(stored_pin_res)

    if stored_pin_hash is None:
        return {
            "status": "error",
            "response": "PIN not found for the provided organization and Digilocker IDs",
        }, 404

    provided_pin_bytes = provided_pin.encode("utf-8")
    stored_pin_hash_bytes = stored_pin_hash.encode("utf-8")

    if bcrypt.checkpw(provided_pin_bytes, stored_pin_hash_bytes):
        return {"status": "success", "response": "PIN verified successfully"}, 200
    else:
        return {"status": "error", "response": "Incorrect PIN"}, 401


def get_pin_from_response(response):
    try:
        if response.get("status") == "success" and "response" in response:
            pin_data = response["response"]
            if isinstance(pin_data, list) and pin_data:
                pin_entry = pin_data[0]
                if isinstance(pin_entry, dict) and "pin" in pin_entry:
                    return pin_entry["pin"]
    except Exception as e:
        VALIDATIONS.log_exception(e)
        print(f"Error extracting PIN: {str(e)}")
    return None


@bp.route("/verify_dob", methods=["POST"])
def verify_dob():
    digilockerid = request.form.get("digilockerid")
    dob = request.form.get("dob")

    date_pattern = r"\b\d{2}-\d{2}-\d{4}\b"
    pattern = re.compile(date_pattern)

    if not digilockerid or not dob:
        return {
            "status": "error",
            "response": "Missing digilockerid or date of birth",
        }, 400

    if not pattern.fullmatch(dob):
        return {
            "status": "error",
            "response": "Date pattern does not match",
        }, 400

    try:

        date_of_birth = datetime.strptime(dob, "%d-%m-%Y").date()

        if date_of_birth > datetime.today().date():
            return {
                "status": "error",
                "response": "Date of birth cannot be in the future",
            }, 400

        today = datetime.today().date()
        age_years = today.year - date_of_birth.year
        if (today.month, today.day) < (date_of_birth.month, date_of_birth.day):
            age_years -= 1

        if age_years <= MIN_AGE:
            return {
                "status": "error",
                "response": f"Age must be greater than {MIN_AGE} years",
            }, 400

        if age_years > MAX_AGE:
            return {
                "status": "error",
                "response": f"Age must be less than {MAX_AGE} years",
            }, 400

        user_dob = get_profile_info(digilockerid)
        stored_date_of_birth_str = user_dob.get("response", {}).get("date_of_birth", "")

        stored_date_of_birth = datetime.strptime(
            stored_date_of_birth_str, "%Y-%m-%dT%H:%M:%S.%fZ"
        )

        stored_date = stored_date_of_birth.date()

        if date_of_birth == stored_date:
            return {
                "status": "success",
                "response": "Date of birth verified successfully",
            }, 200
        else:
            return {"status": "error", "response": "Date of birth does not match"}, 404

    except ValueError:
        return {"status": "error", "response": "Invalid date format"}, 400

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {
            "status": "error",
            "response": f"An error occurred : {str(e)}",
        }, 500


@bp.route("/reset_pin", methods=["POST"])
def reset_pin():
    old_pin = request.form.get("old_pin")
    new_pin = request.form.get("new_pin")

    org_id = request.form.get("org_id")
    digilockerid = request.form.get("digilockerid")

    valid_old_pin = re.match(pin_pattern, old_pin)
    if not valid_old_pin:
        return {
            "status": "error",
            "response": "Please enter valid Old PIN, pattern not match",
        }, 400

    valid_new_pin = re.match(pin_pattern, new_pin)
    if not valid_new_pin:
        return {
            "status": "error",
            "response": "Please enter valid New PIN, pattern not match",
        }, 400

    if not old_pin:
        return {"status": "error", "response": "Old PIN not provided"}, 400

    if not new_pin:
        return {"status": "error", "response": "New PIN not provided"}, 400

    if not org_id:
        return {"status": "error", "response": "Organization ID not provided"}, 400

    if not digilockerid:
        return {"status": "error", "response": "DigiLocker ID not provided"}, 400

    plain_txt = f"{org_id}{digilockerid}"
    auth_id = hashlib.sha256(plain_txt.encode()).hexdigest()

    query = {"auth_id": auth_id}
    fields = {"pin": 1}
    stored_pin_res, status_code = MONGOLIB.org_eve("org_auth", query, fields, limit=1)

    if status_code != 200:
        return {"status": "error", "response": stored_pin_res}, status_code

    stored_pin_hash = get_pin_from_response(stored_pin_res)

    if stored_pin_hash is None:
        return {
            "status": "error",
            "response": "PIN not found for the provided organization and DigiLocker IDs",
        }, 404

    if not bcrypt.checkpw(old_pin.encode("utf-8"), stored_pin_hash.encode("utf-8")):
        return {
            "status": "error",
            "response": "Old PIN does not match",
        }, 400

    salt = bcrypt.gensalt()
    new_hashed_pin = bcrypt.hashpw(new_pin.encode("utf-8"), salt)

    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "pin": new_hashed_pin.decode("utf-8"),
        "updated_on": date_time,
    }

    try:
        res, status_code = MONGOLIB.org_eve_update("org_auth", data, auth_id)

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {
            "status": "error",
            "response": f"An error occurred: {str(e)}",
        }, 500

    if status_code != 200:
        logarray.update({"response": res})
       # RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, "set_pin")
        return res, status_code

    pin_res = RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_auth_update_")
    logarray = {"response": {"org_auth": res, "pin_update": pin_res}}
    logarray.update({"response": {"org_auth": res, "pin_update": pin_res}})
    # RABBITMQ_LOGSTASH.log_stash_logger(logarray, logs_queue, "reset_pin")
    return {"status": "success", "response": "PIN set successfully"}, 200

def get_profile_info(digilockerid):
    try:
        client_id = CONFIG["acsapi_dl"]["client_id"]
        ts = str(int(time.time()))
        plain_text_key_created = (
            CONFIG["credentials"].get(client_id, "") + client_id + digilockerid + ts
        )
        hmac = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
        post_data = {
            "clientid": client_id,
            "ts": ts,
            "user": digilockerid,
            "hmac": hmac,
            "resident_photo": "yes",
        }

        response = requests.post(
            CONFIG["acsapi_dl"]["url"] + "/profile/1.2", data=post_data
        )
        response.raise_for_status()

        if response.status_code == 404:
            return {"status": "error", "response": "Record not found", "code": 404}

        return {"status": "success", "response": response.json(), "code": 200}

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {
            "status": "error",
            "response": f"An error occurred: {str(e)}",
            "code": 500,
        }
        