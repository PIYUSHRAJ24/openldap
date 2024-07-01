from flask import request, Blueprint, g,json
from lib.constants import *
from lib.validations import Validations
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.rabbitmqlogs import RabbitMQLogs
from lib.redislib import RedisLib
import requests
from api.org_activity import activity_insert
import os
import configparser
import hashlib
from lib import otp_service 
otp_connector = otp_service.OTP_services()

get_ttl = configparser.ConfigParser()
get_ttl.read('lib/cache_ttl.ini')

VALIDATIONS = Validations()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()

accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']

bp = Blueprint('org', __name__)
logarray = {}


@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    logarray.update({
        ENDPOINT: request.path,
        HEADERS: {
            'user-agent': request.headers.get('User-Agent'),
            "client_id": request.headers.get("client_id"),
            "ts": request.headers.get("ts"),
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
    logarray[REQUEST].pop('authorization_letter', 0)
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
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 400


@bp.route('/get_role', methods=['GET'])
def get_role():
    try:
        res, status_code = VALIDATIONS.get_org_details(request)
        if status_code != 200:
            return res, status_code
        resp = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], res['post_data'], {})
        logarray.update({RESPONSE: resp[0]})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_role: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/get_details', methods=['GET'])
def get_details():
    try:
        res, status_code = VALIDATIONS.get_org_details(request)
        if status_code != 200:
            return res, status_code
        did = res['post_data'].pop('digilockerid', None) # type: ignore
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], res['post_data'], {})
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        if did:
            res['post_data']['digilockerid'] = did # type: ignore
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], res['post_data'], {}, limit=500)
            if status_code == 400:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_181')}
                logarray.update({RESPONSE: res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return res, 401
            if status_code != 200 or type(res[RESPONSE]) != type([]):
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164')}
                logarray.update({RESPONSE: res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return res, 401
            org_user_details = {}
            for u in res[RESPONSE]:
                if u.get('digilockerid') == did: # type: ignore
                    org_user_details = u
            if org_user_details == {}:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_161')}
                logarray.update({RESPONSE: res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return res, 401
            if org_user_details.get('is_active') != "Y": # type: ignore
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_180')}
                logarray.update({RESPONSE: res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return res, 401
            user_role = org_user_details.get('rule_id') #type: ignore
            resp[RESPONSE][0]['d_incorporation'] = datetime.strptime(resp[RESPONSE][0]['d_incorporation'], D_FORMAT).strftime("%d/%m/%Y") # type: ignore
            resp['current_user_'+RESPONSE] = {**Roles.rule_id(user_role)} # type: ignore
        resp[RESPONSE][0].pop('authorization_letter', 0) # type: ignore
        resp[RESPONSE][0].pop('consent', 0) # type: ignore
        logarray.update({RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/update_details', methods=['POST'])
def update_details(post_data = None):
    try:
        if not post_data:
            res, status_code = VALIDATIONS.update_org_details(request)
            if status_code != 200:
                return res, status_code
            post_data = res['post_data']
        resp = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_details_')
        logarray.update({RESPONSE: resp[0]})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/create_details', methods=['POST'])
def create_details():
    try:
        res, status_code = VALIDATIONS.create_org_details(request)
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        access_post_data = res['access_post_data']
        # Create Entity Profile
        res, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_details"], post_data)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        # Create User Access Rule
        rules_res = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], access_post_data)
        # Link Entity Account with DigiLocker
        did = post_data['dir_info'][0]['digilocker_id'] # type: ignore
        data = {'data': {'digilockerid': did, 'org_id': [post_data['org_id']]}} # type: ignore
        ''''send data to queue in order to process xml'''
        updateXML(did, post_data)
        users_res = RABBITMQ.send_to_queue(data, 'Organization_Xchange', 'org_add_org_user_')
        a = post_data.pop('authorization_letter', 0) # type: ignore
        b = post_data.pop('consent', 0) # type: ignore
        suggest = []
        if post_data.get('name'):
            suggest.append(post_data['name'])
            suggest += post_data['name'].split(" ")
        if post_data.get('email'):
            suggest.append(post_data['email'])
        if post_data.get('org_type'):
            suggest.append(post_data['org_type'])
        # Send Entity Details for searching
        stats_res = ELASTICLIB.send_signup_stats({**post_data, 'suggest': suggest})
        # Save Document Automatically
        MONGOLIB.saveuri(post_data)
        activity_insert("signup","signup",did,post_data['org_id'],post_data['name']) # type: ignore
        logarray.update({RESPONSE: {**res, "rules_res": rules_res[0], "users_res": users_res[0], "stats_res": stats_res}})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        if a:
            post_data.update({'authorization_letter': a}) # type: ignore
        if b:
            post_data.update({'consent': b}) # type: ignore
        return {**res, 'org_id': post_data['org_id']}, 200  # type: ignore
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "create_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


def updateXML(digilockerid, data):
    log_data = {'digilockerid':digilockerid, 'step':'updateXML'}
    try:
        if digilockerid is None:
            log_data['error_description'] = 'lockerid not found'
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return False
        
        uid_token = REDISLIB.get(digilockerid+"_uid_token")
        if uid_token is None:
            log_data['error_description'] = 'uid_token not found in redis'
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return False
        org_id = data.get('org_id')
        queue_data = {
            'digilockerid': digilockerid,
            'uid_token':uid_token,
            'uid_token_hash': hashlib.md5(((str(uid_token)).strip()).encode()).hexdigest(),
            'consent_path': 'esign_consent/'+digilockerid+'_'+data.get('consent'),
            'org_id':org_id
            }
            
        resp, code = RABBITMQ.send_to_queue({"data": queue_data}, 'Organization_Xchange', 'org_update_xml_')
        if code != 200 or resp.get('status') == 'error':
            log_data.update({ RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(log_data, 'Logstash_Xchange', 'org_logs_')
            return False
        
        return True
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: str(e)}
        log_data.update({ RESPONSE: res})
        RABBITMQLOGS.send_to_queue(log_data, 'Logstash_Xchange', 'org_logs_')
        return False
    
    
    
@bp.route('/get_access_rules', methods=['GET'])
def get_access_rules():
    try:
        res, status_code = VALIDATIONS.org_access_rules(request)
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        digilockerid = post_data['digilockerid']
        org_id = post_data['org_id']
        if org_id and digilockerid:
            query = {"org_id": org_id, "digilockerid": digilockerid}
        elif org_id:
            query = {"org_id": org_id}
        else:
            query = {"digilockerid": digilockerid}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        if status_code != 200:
            return res, status_code
        det_res, det_status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], {"org_id": res[RESPONSE][0]['org_id']}, {'name': 1}, limit=1) # type: ignore
        if det_status_code == 200:
            res[RESPONSE] = [{"org_name": det_res[RESPONSE][0]['name'], **Roles.rule_id(x.pop('rule_id')), **x} for x in res[RESPONSE]] # type: ignore
        else:
            res[RESPONSE] = [{**Roles.rule_id(x.pop('rule_id')), **x} for x in res[RESPONSE]] # type: ignore
        logarray.update({RESPONSE: res})
        rule_id = post_data['rule_id']
        query = {"digilockerid": digilockerid} if digilockerid else {"org_id": org_id} if org_id else {"rule_id": rule_id}
        resp = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        logarray.update({ RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_access_rules: " + str(e)}
        logarray.update({ RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/update_access_rules', methods=['POST'])
def update_access_rules():
    try:
        res, status_code = VALIDATIONS.org_access_rules(request)
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        resp = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_rules_')
        logarray.update({RESPONSE: resp})
        act_resp = activity_insert("assign_role","assign_role",post_data['digilockerid'],post_data['org_id'],role_id=post_data['rule_id'],user_affected="") # need user_affected
        logarray.update({"Activity_update": "update_access_rules", RESPONSE: act_resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_access_rules: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/create_access_rules', methods=['POST'])
def create_access_rules():
    try:
        res, status_code = VALIDATIONS.org_access_rules(request, 'C')
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        did = post_data['digilockerid']
        query = {'org_id': post_data['org_id']}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        if status_code != 200:
            return res, status_code
        if len(res[RESPONSE]) == 0 or type(res[RESPONSE]) != type([]):
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_161')}, 208
        data = {'data': {'digilockerid': did, 'org_id': [post_data['org_id']]}}
        resp, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], post_data)
        users_res = RABBITMQ.send_to_queue(data, 'Organization_Xchange', 'org_add_org_user_')
        logarray.update({RESPONSE: {**resp, "users_res": users_res[0]}})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "create_access_rules: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/set_pin', methods=['POST'])
def set_pin():
    try:
        res, status_code = VALIDATIONS.set_pin(request)
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        resp = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'Set_User_Pin_')
        logarray.update({RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return resp
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "set_pin: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400
         

@bp.route('/verify_pin', methods=['POST'])
def verify_pin():
    try:
        res, status_code = VALIDATIONS.verify_pin(request)
        if status_code != 200:
            return res, status_code
        post_data = res['post_data']
        digilockerid = post_data['digilockerid']
        pin = post_data['pin']
        query = {"digilockerid": digilockerid}
        resp, status_code = MONGOLIB.accounts_eve(CONFIG["accounts_eve"]["collection_users"], query, {})
        logarray.update({RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        if status_code == 200:
            res = ORGLIB.match_pin(pin, resp['response'][0]['pin'])  # type: ignore
            if res['status'] == 'success':
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return {STATUS: SUCCESS, "digilockerid": digilockerid}, 200
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_156')}, 400
        else:
            return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "verify_pin_: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/send_mobile_otp', methods=['POST'])
def send_otp_v1():
    try:
        res, status_code = VALIDATIONS.send_otp_v1(request)
        return {STATUS: "success", 'RES': res}, status_code
        if status_code != 200:
            return res, status_code

        if DEBUG_MODE:
            return {
                STATUS: SUCCESS,
                "message": "DigiLocker has sent you an OTP to your registered mobile (xxxxxxxxxx)",
                "msg": "DigiLocker has sent you an OTP to your registered mobile (xxxxxxxxxx)",
                "txn": "29e9898d-bd17-5ba8-9e56-cc75d14b1bd9"
            }, 200
        if REDISLIB.checkAttemptValidateOtp((hashlib.md5((res['post_data'].get('mobile')).encode()).hexdigest())) == False:
            retMsg = {
                STATUS:ERROR,
                ERROR_DES:Errors.error('err_953')
            }
            return retMsg,400
        mobile = res['post_data'].get('mobile')
        res, code = otp_connector.entity_send_mobile_otp(mobile)
        if code == 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res,code
        else:
            return res,400
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "send_otp_v1: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400  
    

@bp.route('/verify_mobile_otp', methods=['POST'])
def verify_otp_v1():
    try:
        res, status_code = VALIDATIONS.verify_otp_v1(request)
        if status_code != 200:
            return res, status_code
        mobile = res['post_data']['mobile']
        otp = res['post_data'].get('otp')
        if DEBUG_MODE:
            REDISLIB.set(mobile+"_verified_udyam_otp", "test")
            return {STATUS: SUCCESS}, 200
        if REDISLIB.checkAttemptValidateOtp((hashlib.md5((mobile + otp).encode()).hexdigest())) == False:
            retMsg = {
                STATUS:ERROR,
                ERROR_DES:Errors.error('err_953')
            }
            return retMsg,400
        resp, code = otp_connector.verify_mobile_otp(mobile,otp)
        if code == 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp,code
        else:
            logarray.update(res)
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, 400
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "verify_otp_v1: " + str(e)}
        logarray.update({ RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400    


@bp.route('/consent', methods=['POST'])
def consent():
    try:
        res, status_code = VALIDATIONS.consent(request)
        if status_code != 200:
            return res, status_code
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "consent: " + str(e)}
        logarray.update({ RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400 
    
