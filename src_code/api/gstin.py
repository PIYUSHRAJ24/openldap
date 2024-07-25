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
from flask import request, Blueprint, g, render_template, jsonify
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

logs_queue = "org_auth_update_"
bp = Blueprint("gstin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())

gstin_pattern = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'

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
            "set_gstin",
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
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route("/set_gstin", methods=["POST"])
def set_gstin():
    gstin = request.form.get("gstin")
    org_id = request.form.get("org_id")
    # digilockerid = request.form.get("digilockerid")

    if not gstin:
        return {"status": "error", "response": "GSTIN number not provided"}, 400

    if not org_id:
        return {"status": "error", "response": "Organization ID not provided"}, 400

    # if not digilockerid:
    #     return {"status": "error", "response": "DigiLocker ID not provided"}, 400

    if not is_valid_gstin(gstin):
        return {
            "status": "error",
            "response": "Please enter valid GSTIN number, pattern not match",
        }, 400
    
    date_time = datetime.now().strftime(D_FORMAT)
    data = {
        "org_id": org_id,
        # "digilockerid": digilockerid,
        "gstin": gstin,
        "updated_on": date_time,
    }

    try:
        res, status_code = MONGOLIB.org_eve_post("org_details", data)
    except Exception as e:
        return {
            "status": "error",
            "error_description": "Technical error",
            "response": str(e),
        }, 400

    if status_code != 200:
        logarray.update({"response": res})
        return res, status_code

    gstin_res = RABBITMQ.send_to_queue(data, "Organization_Xchange", "org_auth_update_")
    logarray.update({"response": {"org_details": res, "gstin_update": gstin_res}})
    return {"status": "success", "response": "GSTIN number set successfully"}, 200


def is_valid_gstin(gstin):
    gstin_pattern = re.compile(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$')
    return bool(gstin_pattern.match(gstin))
