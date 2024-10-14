import hashlib
import random
import uuid
import bcrypt
import requests
import time
import os
import re
import json
import pymongo
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

logs_queue = "org_logs_PROD"
bp = Blueprint("user_status", __name__)
logarray = {}
CONFIG = dict(CONFIG)
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
    g.org_id = request.headers.get("orgid")
    res, status_code = VALIDATIONS.org_id_hmac_authentication(g.org_id)
    if status_code != 200:
        return res, status_code
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
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#1800]"}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return jsonify({STATUS: SUCCESS})


@bp.route("/check_user_status", methods=["GET"])
def check_user_status():
    
    form_data = request.form
    org_id = form_data.get("org_id")
    digilockerid = form_data.get("digilockerid")
    is_active = form_data.get("is_active")

    if not org_id:
        return {STATUS: ERROR, ERROR_DES: "Provide a valid org_id"}, 400

    try:

        if org_id and digilockerid:
            strtohash = org_id + digilockerid
            access_id = hashlib.md5(strtohash.encode()).hexdigest()
            query = {"access_id": access_id}
            
        elif org_id:
            query = {"org_id": org_id}

        if is_active is not None:
            query["is_active"] = is_active   

        res, status_code = MONGOLIB.org_eve(
            CONFIG["org_eve"]["collection_rules"], query, {}, limit=500
        )
        
        response_status = res.get("status")

        if response_status == "success":
            if status_code != 200:
                return {
                    STATUS: SUCCESS,
                    RESPONSE: f"No matching records found for org_id {org_id}",
                }, 404

            else:
                if res["response"]:
                    records = res["response"]
                    response_data = []
                    
                    for record in records:
                        rule_name = Roles.rule_id(record.get("rule_id")).get('rule_name')
                        response_data.append({
                            'org_id': record.get("org_id"),
                            'digilockerid': record.get("digilockerid"),
                            'is_active': record.get("is_active"),
                            'rule_id': rule_name
                        })
                        
                        log_data = {RESPONSE: res["response"]}
                        logarray.update(log_data)
                        RABBITMQLOGS.send_to_queue(
                            logarray, "Logstash_Xchange", logs_queue
                        )
                        
                    return {
                        STATUS: SUCCESS,
                        RESPONSE: response_data
                    }, 200
                else:
                    return {
                        STATUS: SUCCESS,
                        RESPONSE: f"No matching records found for org_id {org_id}",
                    }, 404
        else:
            return {STATUS: ERROR, ERROR_DES: "Failed to fetch data"}, 500

    except Exception as e:
        log_data = {RESPONSE: str(e)}
        logarray.update(log_data)
        RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", logs_queue)
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#1801]"}, 400
    
@bp.route("/org_list", methods=["GET"])
def org_list():
    try:
       
        page = int(request.args.get("page", 1)) 
        org_id = request.form.get("org_id")
        limit = 20
        skip = (page - 1) * limit 
        # print(f"Fetching page {page}, skip={skip}, limit={limit}")  
        if org_id :
            query = {'org_id':org_id}    
        else :
            query = {}
            
        projection = {}       
        res, status_code = MongoLib.org_eve_v2(CONFIG["org_eve"]["collection_details"], query, projection,  sort=[("org_id", 1)], limit=limit, page=skip)

        response_status = res.get("status")

        if response_status == "success" and status_code == 200:
            records = res.get("response", [])
            total_records = res.get("total", len(records))  
            if not records:
                return {
                    STATUS: SUCCESS,
                    RESPONSE: "No matching records found",
                }, 404

            response_data = []

            for record in records:
                org_id = record.get("org_id")
                response_data.append({
                    'org_id': org_id,
                    'org_type': record.get("org_type"),
                    'name': record.get("name"),
                    'pan': record.get("pan"),
                    'd_incorporation': record.get("d_incorporation"),
                    'created_on': record.get("created_on"),
                    'email': record.get("email"),
                    'userifo': userinfo(org_id),  
                    'verification_status': {
                        'is_authorization_letter': 'Y' if record.get("is_authorization_letter") else 'N',
                        'is_pan': 'Y' if record.get("pan") else 'N',
                        'is_cin': 'Y' if record.get("ccin") else 'N'
                    }
                })

            total_pages = (total_records + limit - 1) 
            log_data = {RESPONSE: response_data}
            logarray.update(log_data)
            RABBITMQLOGS.send_to_queue(
                logarray, "Logstash_Xchange", logs_queue
            )

            return {
                STATUS: SUCCESS,
                RESPONSE: response_data,
                "pagination": {
                    "current_page": page,
                    "page_size": limit,
                    "total_pages": total_pages,
                    "total_records": total_records
                }
            }, 200

        else:
            return {STATUS: ERROR, ERROR_DES: "Failed to fetch data"}, 500

    except Exception as e:
        log_data = {RESPONSE: str(e)}
        logarray.update(log_data)
        RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", logs_queue)
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#1802]"}, 400


def userinfo(org_id):
    query = {"org_id": org_id} 
    res, status_code = MONGOLIB.org_eve(
        CONFIG["org_eve"]["collection_rules"], query,{}
    )
    response_status = res.get("status")
    if status_code == 200 and response_status == "success":
        users_data = res.get("response", [])
        digilockerids = [item['digilockerid'] for item in users_data]
        userData = []    
        for digilockerid in digilockerids:
            profileDetails = CommonLib.get_profile_details({'digilockerid': digilockerid})
            userData.append({
                "digilockerid": digilockerid,
                "name": profileDetails.get('username', ''),
                "email": profileDetails.get('email', ''),
                "mobile": profileDetails.get('mobile', '')
            })
        return userData if userData else []
    else:
        log_data = {RESPONSE: str(res)}
        logarray.update(log_data)
        RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", logs_queue)
        print(f"Error fetching user info: {res.get('error', 'Unknown error')}")
        return []
    
