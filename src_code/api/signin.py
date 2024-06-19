import hashlib, random, uuid, bcrypt, requests, time, os, re
from datetime import datetime, timezone
from flask import request, Blueprint, g
from lib.constants import *
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from api.org_activity import activity_insert
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()

logs_queue = "org_sighin_user_"
bp = Blueprint("signin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())


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
        bypass_urls = "healthcheck, get_org_users"
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
            consent_status, consent_code = esign_consent_get()
            if (
                consent_code != 200
                or consent_status.get(STATUS) != SUCCESS
                or not consent_status.get("consent_time")
            ):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            try:
                datetime.datetime.strptime(
                    consent_status.get("consent_time", ""), D_FORMAT
                )
            except Exception:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            g.consent_time = consent_status.get("consent_time")

        logarray.update({"org_id": g.org_id, "digilockerid": g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route("/get_org_users", methods=["GET"])
def get_org_users():
    
    aadhar = request.form.get("aadhar")
    mobile_no = request.form.get("mobile_no")
    
    if not aadhar and not mobile_no:
        return {
            "status": "error",
            "response": "Please enter a valid mobile number or aadhar number",
        }, 400

    if aadhar and not re.match(r"^\d{12}$", aadhar):
        return {"status": "error", "response": "Invalid Aadhar number"}, 400

    if mobile_no and not re.match(r"^\d{10}$", mobile_no):
        return {"status": "error", "response": "Invalid mobile number"}, 400

    if aadhar :
        mobile_uid = aadhar
    else :    
        mobile_uid = mobile_no
        


    #     try:
    #         res, status_code = MONGOLIB.org_eve_post("org_auth", data)
    #     except Exception as e:
    #         if "duplicate key error" in str(e).lower():
    #             return {
    #                 "status": "error",
    #                 "error_description": "Duplicate entry",
    #                 "response": str(e),
    #             }, 400
    #         else:
    #             return {
    #                 "status": "error",
    #                 "error_description": "Technical error",
    #                 "response": str(e),
    #             }, 400

    #     if status_code != 200:
    #         logarray.update({"response": res})
    #        # RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, "pin/set_pin")
    #         return res, status_code

    #     pin_res = RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_auth_update_")
    #     logarray.update({"response": {"org_auth": res, "pin_update": pin_res}})
    #    # RABBITMQ_LOGSTASH.log_stash_logger(logarray, logs_queue, "reset_pin")

    # Assuming additional code here to handle the valid input case
    return {"status": "success", "response": "Valid input received"}, 200
