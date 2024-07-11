from datetime import datetime
import random
import time
import uuid
from flask import request, Blueprint, g,render_template,json, jsonify
from lib.constants import *
from lib.validations import Validations
from lib.elasticlib import ElasticLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.rabbitmqlogs import RabbitMQLogs
from lib.redislib import RedisLib
from lib.commonlib import CommonLib
from lib.connectors3 import Connectors3
from assets.images import default_avatars
from api.name_match import name_match_v3
import requests
from api.org_activity import activity_insert
import os
import configparser
import hashlib
from lib import otp_service 
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
otp_connector = otp_service.OTP_services()

get_ttl = configparser.ConfigParser()
get_ttl.read('lib/cache_ttl.ini')

VALIDATIONS = Validations()
ELASTICLIB = ElasticLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()
CONNECTORS3 = Connectors3()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()

accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']
logs_queue = 'org_logs_PROD'
bp = Blueprint('org', __name__)
logarray = {}


@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    logarray.update({
        ENDPOINT: request.path,
        HEADER: {
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
    
@bp.route('/create_access_rules_v2', methods=['POST'])
def create_access_rules_v2():
    logarray.update({ENDPOINT: 'create_access_rules_v2', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        res, status_code = VALIDATIONS.org_access_rules(request, 'C2')
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        post_data = res['post_data']
        post_data.pop('is_active',0)
        post_data.pop('digilockerid',0)
        post_data.pop('access_id',0)
        rule_name = post_data.pop('rule_name')
        rule_id = Roles.rule_name(rule_name)
        rule_id = "ORGR003" if rule_id == "ORGR001" else rule_id
        din = res['din']
        post_data['rule_id'] = rule_id
        post_data['cin'] = res['cin']
        post_data['din'] = din
        post_data['attempts'] = 0
        post_data['request_status'] = "initiated"
        transaction_id = hashlib.md5((post_data['aadhaar']+post_data['org_id']+rule_id+post_data['updated_on']).encode()).hexdigest()
        post_data['transaction_id'] = transaction_id

        # Admin accounts can be only created by other admins
        if rule_id == 'ORGR003' and g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        # Max user accounts restriction
        # active_users = []
        # for a in g.org_access_rules:
        #     if a.get('is_active') == 'Y':
        #         active_users.append(a)
        # if len(active_users) >= int(CONFIG['roles']['max_users']):
        #     res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_154')}
        #     logarray.update({RESPONSE: res})
        #     RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        #     return res, 400
        
        res, status_code = MONGOLIB.org_eve_post("org_user_requests", post_data)
        logarray.update({RESPONSE: res})
        if status_code == 200:
            res.update({'transaction_id': transaction_id})
        resp, code = get_details()
        
        resp, status_code = RABBITMQ.send_to_queue({
            "data": {
                'recipients': post_data['email'],
                'transaction_id': transaction_id,
                'updated_by': CommonLib.get_profile_details({"digilockerid": post_data['updated_by']}).get('username', ''), # type: ignore
                'org_name': resp[RESPONSE][0]['name'] if code == 200 else '', # type: ignore
                'designation': rule_name,
                'ts': post_data['updated_on'],
                }
            },
            'Email_Xchange',
            'org_add_user_email_'
        )
        if status_code != 200:
            logarray[RESPONSE].update({'email_res': resp})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return resp, status_code
        act_resp = activity_insert("request_created","request_created",g.digilockerid,g.org_id,subjectparams=post_data['email'])
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        REDISLIB.set(transaction_id + '_org_signup_request',json.dumps(post_data),1800)

        return res, status_code
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/create_access_rules_v3', methods=['POST'])
def create_access_rules_v3():
    res, code = create_access_rules_v2()
    return {RESPONSE: CommonLib.aes_encryption(json.dumps(res), g.org_id[:16])}, code
	
@bp.route('/transfer_access', methods=['POST'])
def transfer_access():
    logarray.update({ENDPOINT: 'transfer_access', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001' and g.org_user_details.get('designation') != "director":
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_148')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.transfer_access(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        digilockerid_to = res['digilockerid']
        
        data = {}
        data['digilockerid'] = digilockerid_to
        data['is_active'] = 'Y'
        data['org_id'] =  g.org_id
        data['access_id'] = hashlib.md5((g.org_id+ digilockerid_to).encode()).hexdigest()
        data['rule_id'] = "ORGR001"
        data['designation'] = "director"
        data['updated_by'] =  g.digilockerid
        res, status_code = RABBITMQ.send_to_queue({"data": data}, 'Organization_Xchange', 'org_update_rules_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray.update({RESPONSE: {'trasferee_update': res}})
        
        data['digilockerid'] = g.digilockerid
        data['is_active'] = 'N'
        data['org_id'] =  g.org_id
        data['access_id'] = hashlib.md5((g.org_id+ g.digilockerid).encode()).hexdigest()
        data['updated_by'] =  g.digilockerid
        res = RABBITMQ.send_to_queue({"data": data}, 'Organization_Xchange', 'org_update_rules_')
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray[RESPONSE].update({'trasferer_update': res})
       
        data1 ={}
        data1['org_id'] =  g.org_id
        data1['dir_info'] =[
            {
                'digilocker_id': g.digilockerid,
                'is_active' : 'N'   
            }, {
                'digilocker_id': digilockerid_to,
                'is_active' : 'Y'   
            }
        ]
        res = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
        logarray[RESPONSE].update({"org_details_update": res})
        
        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_101')}
        logarray[RESPONSE].update(res)
        act_resp = activity_insert('transfer_ownership','transfer_ownership',g.digilockerid,g.org_id,user_affected=digilockerid_to)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)           
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400  
		
@bp.route('/revoke_access', methods=['POST'])
def revoke_access():
    ''' 
        Revokes user access if digilockerid is provided,it can be used to change 
        user's role as well by providing digilockerid, with new rule_name.
    '''
    logarray.update({ENDPOINT: 'revoke_access', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.revoke_access(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        post_data = res['post_data']

        did = post_data['digilockerid']
        if did not in [d['digilockerid'] for d in g.org_access_rules]: # type: ignore
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_157')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        rule_id, designation = '', ''
        for r in g.org_access_rules:
            if r['digilockerid'] == did:
                rule_id, designation = r['rule_id'], r.get('designation')      

        # Admin accounts can be only revoked by other admins
        if rule_id == 'ORGR001' and g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        if rule_id == 'ORGR001' and True not in [r['rule_id'] == "ORGR001" and r.get('designation') == "director" and r['is_active'] == "Y" and r['digilockerid'] != did for r in g.org_access_rules]:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_161')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        post_data['org_id'] = g.org_id
        post_data['updated_by'] = g.digilockerid
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_rules_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray.update({RESPONSE: {"org_access_rules_update": res}})

        if rule_id == 'ORGR001' and designation == "director":
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': did, 'is_active' : 'N'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"org_details_update": res})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_102')}
        logarray[RESPONSE].update(res)
        act_resp = activity_insert("user_deactivated","user_deactivated",g.digilockerid,g.org_id,user_affected=did) 
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
		
@bp.route('/grant_access', methods=['POST'])
def grant_access():
    logarray.update({ENDPOINT: 'grant_access', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.grant_access(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        post_data = res['post_data']
        did = post_data['digilockerid']
        
        rule_id, designation = '', ''
        for r in g.org_access_rules:
            if r['digilockerid'] == did:
                rule_id, designation = r['rule_id'], r.get('designation')
        
        # Admin accounts can be only granted access by other admins
        if rule_id == 'ORGR001' and g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        post_data['org_id'] = g.org_id
        post_data['updated_by'] = g.digilockerid
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_rules_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray.update({RESPONSE: {"org_rules_update": res}})
        
        if rule_id == 'ORGR001' and designation == "director":
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': did, 'is_active' : 'Y'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"org_details_update": res})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_103')}
        logarray[RESPONSE].update(res)
        act_resp = activity_insert("user_activated","user_activated",g.digilockerid,g.org_id,user_affected=did)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/assign_access', methods=['POST'])
def assign_access():
    logarray.update({ENDPOINT: 'assign_access', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.assign_access(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        post_data = res['post_data']
        
        did = post_data['digilockerid']
        din = res['din']
        rule_name = post_data['rule_name']
        rule_id = Roles.rule_name(post_data.pop('rule_name'))
        if rule_id == 'ORGR001' and g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        rule_id_org, designation = '', ''
        for r in g.org_access_rules:
            if r['digilockerid'] == did:
                rule_id_org, designation = r['rule_id'], r.get('designation')

        post_data['org_id'] = g.org_id
        post_data['rule_id'] = rule_id
        post_data['updated_by'] = g.digilockerid
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_rules_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray.update({RESPONSE: {"org_rules_update": res}})

        if rule_id == 'ORGR001':
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': did, 'din': din, 'is_active' : 'Y'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray[RESPONSE].update({STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"profile_res": res})

        if rule_id_org == 'ORGR001' and designation == "director" and rule_id != 'ORGR001':
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': did, 'is_active' : 'Y'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray[RESPONSE].update({STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"org_details_update": res})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_105')}
        logarray[RESPONSE].update(res) if logarray.get(RESPONSE) else logarray.update({RESPONSE: res})
        act_resp = activity_insert("assign_role","assign_role",g.digilockerid,g.org_id,user_affected=did, role_id=rule_name)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/update_avatar', methods=['POST'])
def update_avatar():
    logarray.update({ENDPOINT: 'update_avatar', REQUEST: {'org_id': g.org_id}})
    path = g.org_id+'/'
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        status_code, res = VALIDATIONS.upload_file_validation(request)
        if status_code != 200:
            logarray.update({STATUS: ERROR, RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res,status_code
        
        file_name, file_data = res
        upload_res, status_code = CONNECTORS3.file_upload_obj(path, file_name, file_data)
        if status_code != 201:
            logarray.update(upload_res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return upload_res, status_code
  
        logarray.update({RESPONSE: upload_res})
        act_resp = activity_insert("file_created","file_created",user = g.digilockerid,org_id = g.org_id,doc_name=file_name)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        upload_res[MESSAGE] = Messages.message('MSG_106')
        return upload_res, status_code
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/get_avatar', methods=['GET'])
def get_avatar():
    logarray.update({ENDPOINT: 'get_avatar', REQUEST: {'org_id': g.org_id}})
    path = g.org_id+'/'
    filename = 'avataar.jpg'
    try:
        body, content_type = CONNECTORS3.read_obj(path, filename, 'enc')
        if content_type == 400:
            res = {STATUS: SUCCESS, "content_type": 'image/jpeg', "body": default_avatars.entity}
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 200
        res = {STATUS: SUCCESS, "content_type": content_type, "body": str(body)}
        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/send_mobile_otp', methods=['POST'])
def send_otp_v1():
    logarray.update({ENDPOINT: 'send_mobile_otp', REQUEST: dict(request.values)})
    try:
        
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.send_otp_v1(request,g.org_id)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        if REDISLIB.checkAttemptValidateOtp((hashlib.md5((res['post_data'].get('mobile') + g.digilockerid).encode()).hexdigest())) == False: # type: ignore
            retMsg = {
                STATUS:ERROR,
                ERROR_DES:Errors.error('err_953')
            }
            return retMsg,400
        mobile = res['post_data'].get('mobile') # type: ignore
        res, code = otp_connector.entity_send_mobile_otp(mobile)
        if code == 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res,code
        else:
            return res,400
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/verify_mobile_otp', methods=['POST'])
def verify_otp_v1():
    logarray.update({ENDPOINT: 'verify_mobile_otp', REQUEST: dict(request.values)})
    try:
        res, status_code = VALIDATIONS.verify_otp_v1(request,g.org_id)
        if status_code != 200:
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        mobile = res['post_data'].get('mobile')
        otp = res['post_data'].get('otp')
        if REDISLIB.checkAttemptValidateOtp((hashlib.md5((mobile + g.digilockerid).encode()).hexdigest())) == False:
            retMsg = {
                STATUS:ERROR,
                ERROR_DES:Errors.error('err_953')
            }
            return retMsg,400
        res, code = otp_connector.verify_mobile_otp(mobile,otp)
        if code == 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return update_details({"org_id": g.org_id, "mobile": mobile})
        else:
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
       
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/send_email_otp', methods=['POST'])
def send_email_otp():
    logarray.update({ENDPOINT: 'update_avatar', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.send_email_otp(request,g.org_id)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res,status_code
        otp = random.randrange(100000, 999999)
        
        strtohash = g.org_id + g.digilockerid
        md5 = hashlib.md5(strtohash.encode()).hexdigest()
        rediskey = md5 + "_verify_email"

        send_email_otp_attempts = 0
        MAX_ATTEMPTS = 5 #add to config
        ATTEMPT_WINDOW = 3600 #add to config
        TS = int(time.time())
        txn = str(uuid.uuid4())
        redis_data = REDISLIB.get(rediskey)
        if redis_data:
            redis_data = json.loads(redis_data)
            # Check if user has reached maximum attempts within the time window
            if redis_data.get("send_attempts", 0) >= MAX_ATTEMPTS:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('err_953')}
                logarray.update({RESPONSE: res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, 400
            if redis_data.get("attempts", 0) >= MAX_ATTEMPTS and TS - redis_data.get("timestamp", 0) < ATTEMPT_WINDOW:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_181')}
                logarray.update({RESPONSE: res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, 400
        else:
            redis_data = {
                "send_attempts":send_email_otp_attempts,
                "timestamp":TS
            }
            
        data = {
            "data" : {
                'template' : 'reset_email',
                'subject' : 'One Time Password DigiLocker',
                'recipients' : [res["email"]],
                'message' : {'otp':otp, 'ts':datetime.datetime.now().strftime("%Y-%m-%d")},
            }
        }
        email_res, status_code = RABBITMQ.send_to_queue(data, 'Organization_Xchange', 'org_email_update_')
        logarray.update({RESPONSE: {'txn': txn, **email_res}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        if status_code != 200:
            return email_res, status_code
        redis_data['send_attempts'] += 1
        redis_data["attempts"] = 0
        redis_data["otp"] = otp
        redis_data["email"] = res["email"]
        redis_data["txn"] =  txn
        REDISLIB.set(rediskey,json.dumps(redis_data))
        return {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_107'), "txn":txn}
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/verify_email_otp', methods=['POST'])
def verify_email_otp():
    logarray.update({ENDPOINT: 'verify_email_otp', REQUEST: dict(request.values)})
    try:
        res, status_code = VALIDATIONS.verify_email_otp(request,g.org_id)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        otp = res['otp']
        txn = res['txn']
        strtohash = g.org_id + g.digilockerid
        md5 = hashlib.md5(strtohash.encode()).hexdigest()
        rediskey = str(md5) + "_verify_email"

        redisdata = REDISLIB.get(rediskey)
        if redisdata:
            redisdata = json.loads(redisdata)
            if redisdata['txn'] != txn:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_134')}
                logarray.update({RESPONSE: res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, 400
            if redisdata["attempts"] > int(CONFIG["otp"]["email_attempts"])-1:
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_158')}
                logarray.update({RESPONSE: res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, 400
            
            if int(otp) == redisdata['otp']:
                postdata = {
                    "org_id": g.org_id,
                    "email" : redisdata["email"]
                }
                logarray.update({RESPONSE: {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_108')}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint) 
                return update_details(postdata)
            else:
                redisdata["attempts"] += 1
                REDISLIB.set(rediskey,json.dumps(redisdata),REDISLIB.ttl(rediskey))
                no_of_attempts= int(CONFIG["otp"]["email_attempts"])-int(redisdata["attempts"])
                res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_159')%str(no_of_attempts)}
                logarray.update({RESPONSE: res})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)   
                return res, 400
        res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_110')}
        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)   
        return res, 404
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/searchentity', methods=['GET'])
def search_entity():
    query = request.args.get('q')
    if not query:
        return jsonify({'error': 'Query parameter is required'})
    try:
        results = ELASTICLIB.search_cin(query)
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'results': []})
    
@bp.route('/search_regulators', methods=['GET'])
def search_regulators():
    query = request.args.get('q')
    if not query:
        return jsonify({'error': 'Query parameter is required'})
    try:
        results = ELASTICLIB.search_entity(query)
        # return jsonify({'results': results})
        return {
                "results": [
                    {
                        "c_identifier": "SEBI-XXXXXXXX",
                        "org_id": "2d3d1e79-95bd-458d-92a7-908fc0ff9bb8",
                        "org_name": "Securities and Exchange Board of India"
                    },
                    {
                        "c_identifier": "NFRA-XXXXXXXX",
                        "org_id": "2d666eb0-5a06-44d1-a78d-f9a9a9b5facb",
                        "org_name": "National Financial Reporting Authority"
                    }]
                }
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "No Data Found(#EX-400)"}, 400

@bp.route('/get_user_request', methods=['POST'])
def get_user_request():
    transaction_id = request.values.get('transaction_id')
    logarray.update({ENDPOINT: 'get_user_request', REQUEST: {'transaction_id': transaction_id}})
    if not transaction_id:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: Errors.error("ERR_MSG_173")}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 400

    if not REDISLIB.get(transaction_id + '_org_signup_request'):
        res, status_code = MONGOLIB.org_eve("org_user_requests", {'transaction_id': transaction_id}, {})
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        if len(res[RESPONSE]) == 1:
            if not res[RESPONSE][0].get('rejected_on'): # type: ignore
                CommonLib().update_request(transaction_id, "expired", True)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_175")}, 400
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 400
    
    try:
        res, status_code = MONGOLIB.org_eve("org_user_requests", {'transaction_id': transaction_id}, {})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code

        if len(res[RESPONSE]) == 0:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_110")}, 400
        elif len(res[RESPONSE]) != 1:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_168")}, 400
        
        if res[RESPONSE][0].get('request_status') == "created": # type: ignore
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_179")}, 400
    
        if res[RESPONSE][0].get('rejected_on'): # type: ignore
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_178")%res[RESPONSE][0].get('request_status')}, 400 # type: ignore

        attempts = int(res[RESPONSE][0].get('attempts', 0)) # type: ignore
        ################################ attempts from config
        if attempts >= 5:
            CommonLib().update_request(transaction_id, "expired", True)
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_180")}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res[RESPONSE][0]['updated_by'] = CommonLib.get_profile_details({"digilockerid" :res[RESPONSE][0].get('updated_by')}).get('username', '') # type: ignore
        g.org_id = res[RESPONSE][0]['org_id'] # type: ignore
        g.role = ""
        g.digilockerid = ""
        res[RESPONSE][0]['rights'] = Roles.rule_id(res[RESPONSE][0].pop('rule_id', 0)) # type: ignore
        res[RESPONSE][0].pop('mobile', 0) # type: ignore
        res[RESPONSE][0].pop('email', 0) # type: ignore
        resp, code = get_details()
        res[RESPONSE][0]['org_name'] = resp[RESPONSE][0]['name'] if code == 200 else '' # type: ignore
        resp, code = get_avatar()
        res[RESPONSE][0]['avatar'] = resp['body'] if code == 200 else default_avatars.entity # type: ignore
        
        post_data = {
            'attempts': attempts+1
        }
        MONGOLIB.org_eve_patch("org_user_requests/"+transaction_id, post_data)
        logarray.update({RESPONSE: res[RESPONSE]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, status_code
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/get_user_requests', methods=['GET'])
def get_user_requests():
    req = {'org_id': g.org_id}
    logarray.update({ENDPOINT: 'get_user_requests', REQUEST: req})
    try:
        res, status_code = MONGOLIB.org_eve("org_user_requests", req, {}, limit = 1000)
        if status_code == 400:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: SUCCESS, RESPONSE: []}, 200
        logarray.update({RESPONSE: res})
        data = []
        if len(res[RESPONSE]) > 0:
            for d in res[RESPONSE]:
                d['updated_by'] = CommonLib.get_profile_details({"digilockerid" :d.get('updated_by')}).get('username', '') # type: ignore
                d['rule_name'] = Roles.rule_id(d.pop('rule_id', 0)).get('rule_name', '').title() # type: ignore
                d.pop('mobile', 0) # type: ignore
                d.pop('aadhaar', 0) # type: ignore
                d.pop('org_id', 0) # type: ignore
                if d.get('rejected_by') and d['rejected_by'] != "system": # type: ignore
                    d['rejected_by'] = CommonLib.get_profile_details({"digilockerid": d['rejected_by']}).get('username', '') # type: ignore
                if d.get('request_status') == "initiated" and (datetime.datetime.now() > datetime.datetime.strptime(d['updated_on'], D_FORMAT) + datetime.timedelta(minutes=30) or int(d.get('attempts', 0)) >= 5):
                    d['request_status'] = "expired"
                    d['rejected_by'] = "system"
                    d['rejected_on'] = datetime.datetime.now().strftime(D_FORMAT)
                    CommonLib().update_request(d['transaction_id'], "expired", True)
                data.append(d)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: SUCCESS, RESPONSE: data}, status_code
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/cancel_user_request', methods=['POST'])
def cancel_user_request():
    
    if g.role != 'ORGR001':
        res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 400
    
    transaction_id = request.values.get('transaction_id')
    if not transaction_id:
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 400
    logarray.update({ENDPOINT: 'cancel_user_request', REQUEST: {'transaction_id': transaction_id}})
    
    try:
        res, status_code = MONGOLIB.org_eve("org_user_requests", {'transaction_id': transaction_id}, {})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        if len(res[RESPONSE]) == 0:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_110")}, 400
        elif len(res[RESPONSE]) > 1:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_168")}, 400
        if res[RESPONSE][0].get('org_id') != g.org_id: # type: ignore
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_160')}, 401
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 401
        if res[RESPONSE][0].get('request_status') == "created": # type: ignore
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_179")}, 400
        if res[RESPONSE][0].get('rejected_on'): # type: ignore
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_177")}, 400
        email = res[RESPONSE][0].get('email') # type: ignore
        res, status_code = CommonLib().update_request(transaction_id, "cancelled")
        act_resp = activity_insert("request_cancelled","request_cancelled",g.digilockerid,g.org_id,subjectparams=email)
        logarray.update({RESPONSE: res, "activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, status_code
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/create_org_user', methods=['POST'])
def create_org_user():
    transaction_id = request.values.get('transaction_id')
    logarray.update({ENDPOINT: 'create_org_user', REQUEST: {'transaction_id': transaction_id}})
    
    if not transaction_id:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: Errors.error("ERR_MSG_173")}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 400

    # Use resident name from redis at verify otp

    if not REDISLIB.get(g.digilockerid+'_org_add_user_verify_otp'):
        res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_160')}, 401
        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return render_template(FORCED_ACCESS_TEMPLATE)

    try:
        res, status_code = CommonLib().create_org_user(transaction_id, g.digilockerid)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        post_data = res['post_data'] # type: ignore
        din = res['din'] # type: ignore
        rule_id = post_data['rule_id'] # type: ignore
        rule_name = Roles.rule_id(rule_id)['rule_name']
        
        res, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], post_data)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code

        data = {'data': {'digilockerid': g.digilockerid, 'org_id': [post_data['org_id'] or g.org_id]}} # type: ignore
        users_res = RABBITMQ.send_to_queue(data, 'Organization_Xchange', 'org_add_org_user_')
        logarray.update({RESPONSE: {'org_access_rules_create': res, 'users_update': users_res}})

        if rule_id == 'ORGR001' and post_data['designation'] == "director": # type: ignore
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': g.digilockerid, 'din': din, 'is_active' : 'Y'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"org_details_update": res})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_100')}
        logarray[RESPONSE].update(res)
        act_resp = activity_insert("user_added","user_added",post_data['updated_by'], # type: ignore
            g.org_id,user_affected=g.digilockerid,role_id=rule_name)
        logarray[RESPONSE].update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        REDISLIB.remove(g.digilockerid+'_org_add_user_verify_otp')
        MONGOLIB.org_eve_patch("org_user_requests/"+transaction_id, {'request_status': "created"})
        return res, 200
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/update_cin_profile', methods=['POST'])
def update_cin_profile():
    try:
        
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        res, status_code = VALIDATIONS.is_valid_cin_v2(request, g.org_id)
        if status_code != 200:
            return res, status_code
        
        cin = res.get("cin")
        din = res.get("din")

        # CIN Verification
        url = CONFIG['mca']['cin_url']+cin
        headers = {
            'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
            'X-APISETU-CLIENTID': CONFIG['mca']['client_id']
        }
        try:
            response = requests.request("GET", url=url, headers=headers, timeout=10)
        except requests.exceptions.ReadTimeout:
            try:
                response = requests.request("GET", url=url, headers=headers, timeout=10)
            except requests.exceptions.ReadTimeout:
                try:
                    response = requests.request("GET", url=url, headers=headers, timeout=10)
                except requests.exceptions.ReadTimeout:
                    logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: Errors.error("ERR_MSG_155")+" - mca read timed out"}})
                    RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_155")}, 400

        if response.status_code != 200:
            logarray.update({RESPONSE: response})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_185")}, 400
        else:
            res = json.loads(response.text)
            company_name_api = res.get("companyName")

        req = {'org_id': g.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], req, {'name': 1, 'cin': 1, 'udyam': 1})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        if VALIDATIONS.is_valid_cin(res.get("response", [{}])[0].get("cin", None)):
            res = {STATUS: ERROR, ERROR: Errors.error('ERR_MSG_200')}
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        if VALIDATIONS.is_valid_udyam_number(res.get("response", [{}])[0].get("udyam", None))[1] == 200:
            res = {STATUS: ERROR, ERROR: Errors.error('ERR_MSG_201')}
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        original_name = res.get("response", [{}])[0].get("name", None)
        resp = name_match_v3(company_name_api, original_name)
        if resp["status"] != "success":
            logarray.update({RESPONSE: {'status_code': status_code, RESPONSE: resp}})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_165")}, 400 

        # DIN Verification
        url = CONFIG['mca']['din_url'] + cin
        headers = {
            'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
            'X-APISETU-CLIENTID': CONFIG['mca']['client_id']
        }
        try:
            response = requests.request("GET", url=url, headers=headers, timeout=10)
        except requests.exceptions.ReadTimeout:
            try:
                response = requests.request("GET", url=url, headers=headers, timeout=10)
            except requests.exceptions.ReadTimeout:
                try:
                    response = requests.request("GET", url=url, headers=headers, timeout=10)
                except requests.exceptions.ReadTimeout:
                    logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: Errors.error("ERR_MSG_164")+" - mca read timed out"}})
                    RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_155")}, 400

        original_name = ''
        try:
            res = json.loads(response.text)
        except Exception:
            res = {}

        if response.status_code != 200:
            res = {STATUS: ERROR, RESPONSE: "din service failed. "+res.get('error', response.text)}
            logarray.update({RESPONSE:res})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_202")}, 400
        
        if not any([d['din'] == din for d in res]):
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_203')}
            logarray.update({RESPONSE:res})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        for i in res:
            if i['din'] == din:
                original_name = i['name']
            
        username = CommonLib.get_profile_details({'digilockerid': g.digilockerid}).get('username', '')
        resp = name_match_v3(username, original_name)
        if resp["status"] != "success":
            logarray.update({RESPONSE: {'status_code': status_code, RESPONSE: resp}})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_198")}, 400 

        # Update CIN and DIN
        post_data = {"org_id":g.org_id, 'ccin':cin, 'dir_info': [{'digilocker_id': g.digilockerid, 'din': din[2:], 'is_active' : 'Y'}]}
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_details_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        act_resp = activity_insert("cin_updated","cin_updated",g.digilockerid,g.org_id,user_affected="",subjectparams=cin)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint) 
        return {STATUS: SUCCESS, RESPONSE: Messages.message('MSG_110')}
        
    except Exception as e:
        print(f"Exception occurred: {e}")
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/update_icai_profile', methods=['POST'])
def update_icai_profile():
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.is_valid_icai(request, g.org_id)
        if status_code != 200:
            return res, status_code

        icai = res.get("icai")
        post_data = {"org_id":g.org_id, 'icai':icai}
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_details_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        else:
            # Send Entity Details for searching
            stats_res = ELASTICLIB.send_signup_stats(post_data)
            act_resp = activity_insert("icai_updated","icai_updated",g.digilockerid,g.org_id,user_affected="",subjectparams=icai)
            logarray.update({"activity_update": act_resp[0]})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return {STATUS: SUCCESS, RESPONSE: Messages.message('MSG_111')}
    
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
@bp.route('/esign_consent_get', methods=['GET'])
def esign_consent_get():
    try:
        req = {'org_id': g.org_id}
        rediskey = g.org_id + '_esign_consent_get'
        redis_data = REDISLIB.get(rediskey)
        if redis_data:
            redis_data = json.loads(redis_data)
            logarray.update({RESPONSE: {'response': redis_data, 'request': req}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return redis_data, 200

        res, status_code = MONGOLIB.accounts_eve_v2("esign_consent", req, {})
        if status_code == 200 and res.get('status') == 'success' and res.get('response') is not None:
            created_on = created_on = res.get('response')[0].get('created_on')  # Extract created_on field from the response
            res = {
                STATUS: SUCCESS,
                'consent_time': created_on  # Include created_on field in the response
            }
            REDISLIB.set(rediskey, json.dumps(res), 1800)
            logarray.update({RESPONSE: {'response': res, 'request': req}})
            return res, 200

        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: SUCCESS, 'consent_time': ''}, 200
    except Exception as e:
        res = {STATUS: ERROR, RESPONSE: str(e) + "[#002]"}
        RABBITMQ_LOGSTASH.log_stash_logeer(res, logs_queue, g.endpoint)
        res[RESPONSE] = Errors.error('ERR_MSG_111') + "[#002]"
        return res, 400
    
@bp.route('/update_udyam_profile', methods=['POST'])
def update_udyam_profile():
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        res, status_code = VALIDATIONS.is_valid_udcer(request)
        if status_code != 200:
            logarray.update({RESPONSE:res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        company_name_api = res[RESPONSE]['enterprise_name']
        udyam = res[RESPONSE]['udyam']
        req = {'org_id': g.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], req, {'name': 1, 'cin': 1, 'udyam': 1})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        if VALIDATIONS.is_valid_cin(res.get("response", [{}])[0].get("cin", None)):
            res = {STATUS: ERROR, ERROR: Errors.error('ERR_MSG_200')}
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        if VALIDATIONS.is_valid_udyam_number(res.get("response", [{}])[0].get("udyam", None))[1] == 200:
            res = {STATUS: ERROR, ERROR: Errors.error('ERR_MSG_201')}
            logarray.update(res)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        original_name = res.get("response", [{}])[0].get("name", None)
        resp = name_match_v3(company_name_api, original_name)
        if resp["status"] != "success":
            logarray.update({RESPONSE: {'status_code': status_code, RESPONSE: resp}})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_197")}, 400
        
        post_data = {"org_id":g.org_id, 'udyam':udyam}
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_details_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        
        # Send Entity Details for searching
        act_resp = activity_insert("udyam_updated","udyam_updated",g.digilockerid,g.org_id,user_affected="",subjectparams=udyam)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint) 
        return {STATUS: SUCCESS, RESPONSE: Messages.message('MSG_110')}
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        print(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    
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
        mobile = request.form.get('mobile')
        res, status_code = VALIDATIONS.send_otp_v1(request)
        
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
    
