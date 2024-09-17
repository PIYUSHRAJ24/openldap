import base64
import random
import string
from flask import request, Blueprint, g,json
from lib.constants_auth import *
from lib.validations_auth import Validations
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.rabbitmqlogs import RabbitMQLogs
from lib.redislib import RedisLib
from lib.orglib import OrgLib
from lib.elasticlib import ElasticLib
from api.section import list_section
import requests
from api.org_activity import activity_insert
import os
import configparser
import hashlib
from lib import otp_service

from lib.commonlib_auth import CommonLib
from lib.drivejwt_auth import DriveJwt
otp_connector = otp_service.OTP_services()

get_ttl = configparser.ConfigParser()
get_ttl.read('lib/cache_ttl.ini')

VALIDATIONS = Validations()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()
# ELASTICLIB = ElasticLib()

accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']
ORGLIB = OrgLib()

bp = Blueprint('permission', __name__)
logarray = {}

@bp.before_request
def validate_user():
    """
        JWT Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.path
        jwtlib = DriveJwt(request)
        
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
        g.user_rules = jwtlib.user_rules
        g.user_departments = jwtlib.user_departments
        g.org_access_functions = jwtlib.org_access_functions
        g.org_ds_fn_roles = jwtlib.org_ds_fn_roles
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
        

        
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13000]"}, 401
    
@staticmethod
def ds_fn_roles(act, access_id):
    try:
        if g.role == "ORGR001":
            return {STATUS: SUCCESS}, 200
        elif g.role == "ORGR003":
            for b in g.org_access_rules:
                if access_id == b.get('access_id') and b.get('rule_id') != "ORGR002" and b.get('is_active') == "Y":
                    return {STATUS: SUCCESS}, 200
            return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400
        elif g.role == "ORGR002":
            for b in g.org_access_rules:
                if access_id == b.get('access_id') and b.get('rule_id') != "ORGR002" and b.get('is_active') == "Y":
                    return {STATUS: SUCCESS}, 200
            return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400
        return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400
        
    except Exception as e:
        print({STATUS: ERROR, ERROR_DES: str(e)})
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "Failed to verify user permission."}, 400

@bp.route('/list', methods=['POST'])
def list_department():
    try:
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_func"], {}, {},limit=500)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        
        data = []

        for d in resp[RESPONSE]:
            
                data.append(d)
           
                
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13001]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400

@bp.route('/update', methods=['POST'])
def update():
    try:
        
        res,status_code = VALIDATIONS.update_org_permission(request)
        if status_code != 200:
            return res, status_code
        
        act = 'update permission'
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        
        fn_id = res['access_post_data'].pop('fn_id', None)
        access_post_data = res['access_post_data']
        
        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_func"], access_post_data, fn_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13002]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400


@bp.route('/create', methods=['POST'])
def create():
    try:
        
        res, status_code = VALIDATIONS.create_org_permission(request)
        if status_code != 200:
            return res, status_code
        act = 'create permission'
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_func"], res)
        if status_code != 200:
            logarray.update({RESPONSE: resd})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resd, status_code
        return resd, status_code
        # activity_insert("created_by","signup",did,post_data['org_id'],post_data['name']) # type: ignore
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13003]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/view', methods=['POST'])
def view():
    
    try:
        for access_id in g.org_access_rules:
            if access_id['digilockerid'] == g.digilockerid  and access_id['is_active']=="Y" and access_id.get('fn_id') != None:
                data = {
                    "org_id":g.org_id,
                    "rule_id": access_id['rule_id'],
                    "fn_id" : access_id['fn_id']
                }
                resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_fu_roles"], data, {},limit=500)
                if status_code != 200:
                    logarray.update({RESPONSE: resp})
                    RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return resp, status_code
                    
        data = []   

        for d in resp[RESPONSE]:
            
                data.append(d)
           
                
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13004]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/user_permission', methods=['POST'])
def user_permission():
    try:
        
        res, status_code = VALIDATIONS.user_org_permission(request)
        if status_code != 200:
            return res, status_code
        
        act = 'allowed user permission'
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        fn_id = g.org_access_functions.get(res['fn_name'])
        
        access_user = hashlib.md5((g.org_id+res['digilockerid']).encode()).hexdigest()
        for a in g.org_access_rules:
            if a['access_id'] == access_user and a['is_active'] != "N":
                
                rule_id = a['rule_id']
                data = {
                                "org_id": g.org_id,
                                "digilockerid": res['digilockerid'],
                                "fn_id":fn_id['fn_id'],
                                "rule_id": rule_id,
                                "is_active": "Y",
                                "access_id": hashlib.md5((g.org_id+res['digilockerid']+fn_id['fn_id']).encode()).hexdigest(),
                                "updated_by" : g.digilockerid,
                                "updated_on": datetime.now().strftime(D_FORMAT)
                            }
        
                
                resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], data)
                if status_code != 200:
                    logarray.update({RESPONSE: resd})
                    RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return resd, status_code
                data.pop("digilockerid",None)
                data.pop("updated_by",None)
                resp, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_fu_roles"], data)
                if status_code != 200:
                    logarray.update({RESPONSE: resp})
                    RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return resp, status_code
                return resd, status_code
        return res, status_code
        # activity_insert("created_by","signup",did,post_data['org_id'],post_data['name']) # type: ignore
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13005]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
