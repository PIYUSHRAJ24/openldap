import datetime
import hashlib
import random
import uuid
from flask import request, Blueprint, g, render_template, jsonify
import requests
import os
import time
from lib.constants import *
from lib.validations import Validations
# from lib.elasticlib import ElasticLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.connectors3 import Connectors3
from api.org_activity  import activity_insert
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.aadhaarServices import AADHAAR_services
from api.name_match import name_match_v3
from assets.images import default_avatars
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

VALIDATIONS = Validations()
# ELASTICLIB = ElasticLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()
CONNECTORS3 = Connectors3()
AADHAAR_CONNECTOR = AADHAAR_services(CONFIG)
from lib import otp_service 
otp_connector = otp_service.OTP_services()
logs_queue = 'org_logs_PROD'
bp = Blueprint('org', __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

@bp.before_request
def validate():
    """
        JWT Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        org_bypass_urls = ('create_org_user')
        g.endpoint = request.path
        if request.path.split('/')[-1] == "get_user_request":
            res, status_code = CommonLib().validation_rules(request, True)
            if status_code != 200:
                return res, status_code
            logarray.update({ENDPOINT: g.endpoint, REQUEST: {'user': res[0], 'client_id': res[1]}})
            return

        jwtlib = DriveJwt(request, CONFIG)
        if request.path.split('/')[-1] in org_bypass_urls:
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
        g.consent_time = ''
        consent_bypass_urls = ('get_details','get_access_rules', 'get_users','get_authorization_letter','get_access_rules','update_avatar','get_avatar','send_mobile_otp','verify_mobile_otp','send_email_otp','verify_email_otp','get_user_request','get_user_requests','update_cin_profile','update_icai_profile','update_udyam_profile','esign_consent_get')
        if request.path.split('/')[1] not in consent_bypass_urls and request.path.split('/')[-1] not in consent_bypass_urls:
            consent_status, consent_code = esign_consent_get()
            if consent_code != 200 or consent_status.get(STATUS) != SUCCESS or not consent_status.get('consent_time'):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            try:
                datetime.datetime.strptime(consent_status.get('consent_time', ''), D_FORMAT)
            except Exception:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            g.consent_time = consent_status.get('consent_time')
            
        logarray.update({'org_id': g.org_id, 'digilockerid': g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route('/', methods=['GET', 'POST'])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route('/get_count', methods=['POST'])
def get_count():
    res, status_code = VALIDATIONS.org_doc_count(request)
    if status_code != 200:
        return res, status_code
    org_id = res['org_id']
    es_date = res['date'] = res['date'] if res['date'] != None else datetime.datetime.now().strftime("%Y-%m-%d")
    return ELASTICLIB.search(CONFIG['elasticsearch']['idss_index'], org_id, es_date)

@bp.route('/list_sub_entities', methods=['GET'])
def list_sub_entities():
    return {
        'departments': g.dept_details,
        'sections': g.sec_details
    }

@bp.route('/get_details', methods=['GET'])
def get_details():
    req = {'org_id': g.org_id}
    logarray.update({ENDPOINT: 'get_details', REQUEST: req})
    try:
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], req, {})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code

        for r in res[RESPONSE]:
            r['d_incorporation'] = datetime.datetime.strptime(r['d_incorporation'], D_FORMAT).strftime("%d/%m/%Y") # type: ignore
            if r.get('org_type'): # type: ignore
                r['org_type'] = r['org_type'].lower() # type: ignore
            r['is_authorization_letter'] = r.get('is_authorization_letter') if r.get('is_authorization_letter') else 'N'
            r.pop('authorization_letter', None) # type: ignore
            if not r.get('ccin'): # type: ignore
                r['ccin'] = None # type: ignore
            if not r.get('icai'): # type: ignore
                r['icai'] = None # type: ignore
            if not r.get('udyam'): # type: ignore
                r['udyam'] = None # type: ignore
            r.pop('consent', None) # type: ignore
            cres = esign_consent_get()
            g.consent_time = cres[0].get('consent_time', '')
            r['consent_time'] = g.consent_time # type: ignore
        res['current_user_'+RESPONSE] = {'digilockerid': g.digilockerid, **Roles.rule_id(g.role), **CommonLib.get_profile_details({'digilockerid': g.digilockerid})} # type: ignore
        log_data = {RESPONSE: res}
        logarray.update(log_data)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, status_code
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


@bp.route('/get_authorization_letter', methods=['GET'])
def get_authorization_letter():
    req = {'org_id': g.org_id}
    logarray.update({ENDPOINT: 'get_authorization_letter', REQUEST: req})
    try:
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], req, {})
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        if not res[RESPONSE][0].get('authorization_letter'): # type: ignore
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_110')}, 400
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        res = {STATUS: SUCCESS, "content_type": "application/pdf", "body": res[RESPONSE][0]['authorization_letter']} # type: ignore
        logarray.update(res)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, status_code
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


@bp.route('/update_profile', methods=['POST'])
def update_details(post_data = None):
    logarray.update({ENDPOINT: 'update_profile', REQUEST: post_data or request.json})
    try:
        if not post_data:
            res, status_code = VALIDATIONS.update_org_details(request, g.org_id)
            if status_code != 200:
                logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            post_data = res['post_data']
        
        res, status_code = RABBITMQ.send_to_queue({"data": post_data}, 'Organization_Xchange', 'org_update_details_')
        if status_code != 200:
            logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code
        logarray.update({RESPONSE: {'org_details_update': res}})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_104')}
        logarray[RESPONSE].update(res)
        subjectparams = post_data.get('email') or post_data.get('mobile') # type: ignore
        subject = "email_updated" if post_data.get('email') else "mobile_updated" # type: ignore
        act_resp = activity_insert(subject,subject,g.digilockerid,g.org_id,user_affected="",subjectparams=subjectparams) 
        logarray.update({RESPONSE: res, "activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: str(e)}})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


@bp.route('/get_users', methods=['GET'])
def get_users():
    logarray.update({ENDPOINT: 'get_users', REQUEST: {'org_id': g.org_id}})
    try:
        unique_users = {}
        for rule in g.org_access_rules:
            digilockerid = rule.get('digilockerid')
            if digilockerid not in unique_users.keys() and not rule.get('dept_id') and not rule.get('sec_id'):
                unique_users[digilockerid] = {
                    'profile': CommonLib.get_profile_details({'digilockerid':digilockerid}),
                    **Roles.rule_id(rule.pop('rule_id')),
                    **rule,
                    'departments': [],
                    'sections': []
                }
            elif rule.get('dept_id') and not rule.get('sec_id'):
                unique_users[digilockerid]['departments'].append({
                    "dept_name": g.dept_details.get(rule.get('dept_id'),{}).get("name",""),
                    **Roles.rule_id(rule.pop('rule_id')),
                })
            elif rule.get('sec_id'):
                unique_users[digilockerid]['sections'].append({
                    "sec_name": g.sec_details.get(rule.get('sec_id'),{}).get("name",""),
                    **Roles.rule_id(rule.pop('rule_id')),
                })

        res = {STATUS: SUCCESS, RESPONSE: list(unique_users.values()), 'count': len(list(unique_users.values()))}
        logarray.update(res)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/get_access_rules', methods=['GET'])
def get_access_rules():
    logarray.update({ENDPOINT: 'get_access_rules', REQUEST: {'org_id': g.org_id}})
    try:
        
        user_details = [{
                'profile': CommonLib.get_profile_details(x),
                **Roles.rule_id(x.pop('rule_id')), **x,
                'is_loggedin': "Y" if x.get('digilockerid') == g.digilockerid else "N",
                "dept_name": g.dept_details.get(x.get('dept_id'),{}).get("name",""),
                "sec_name": g.sec_details.get(x.get('sec_id'),{}).get("name","")
            } for x in g.org_access_rules]
        user_access_requests, status_code = get_user_access_requests()
        if status_code == 200 and len(user_access_requests[RESPONSE])>0:
            user_details += user_access_requests[RESPONSE]
        res = {STATUS: SUCCESS, RESPONSE: user_details}
        logarray.update(res)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


@bp.route('/get_designation', methods=['GET'])
def get_designation():
    logarray.update({ENDPOINT: 'get_designation', REQUEST: {'org_id': g.org_id}})
    try:
        res = {STATUS: SUCCESS, RESPONSE: CONFIG['roles']['designation'].split(",")}
        logarray.update({RESPONSE: res})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


@bp.route('/create_access_rules', methods=['POST'])
def create_access_rules():
    logarray.update({ENDPOINT: 'create_access_rules', REQUEST: dict(request.values)})
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        res, status_code = VALIDATIONS.org_access_rules(request, 'C')
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code

        post_data = res['post_data']
        did = post_data['digilockerid']
        if not REDISLIB.get(did+'_org_add_user_verify_otp'):
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_160')}, 401
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return render_template(FORCED_ACCESS_TEMPLATE)

        din = res['din']
        rule_name = post_data['rule_name']
        rule_id = Roles.rule_name(post_data.pop('rule_name'))

        # Admin accounts can be only created by other admins
        if rule_id == 'ORGR001' and g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400
        
        # Same accounts can not be added
        if did in [d['digilockerid'] for d in g.org_access_rules]: # type: ignore
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_156')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        # Max user accounts restriction
        active_users = []
        for a in g.org_access_rules:
            if a.get('is_active') == 'Y':
                active_users.append(a)
        if len(active_users) >= int(CONFIG['roles']['max_users']):
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_154')}
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, 400

        post_data['org_id'] = g.org_id
        post_data['rule_id'] = rule_id
        post_data['updated_by'] = g.digilockerid

        res, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], post_data)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
            return res, status_code

        data = {'data': {'digilockerid': did, 'org_id': [post_data['org_id'] or g.org_id]}}
        users_res = RABBITMQ.send_to_queue(data, 'Organization_Xchange', 'org_add_org_user_')
        logarray.update({RESPONSE: {'org_access_rules_create': res, 'users_update': users_res}})

        if rule_id == 'ORGR001' and post_data['designation'] == "director":
            data1 = {'org_id': g.org_id, 'dir_info': [{'digilocker_id': did, 'din': din, 'is_active' : 'Y'}]}
            res, status_code = RABBITMQ.send_to_queue({"data": data1}, 'Organization_Xchange', 'org_update_details_')
            if status_code != 200:
                logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: res.pop(RESPONSE) if res.get(RESPONSE) else res}})
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
                return res, status_code
            logarray[RESPONSE].update({"org_details_update": res})

        res = {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_100')}
        logarray[RESPONSE].update(res)
        act_resp = activity_insert("user_added","user_added",g.digilockerid,g.org_id,user_affected=did,role_id=rule_name)
        logarray.update({"activity_update": act_resp[0]})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        REDISLIB.remove(did+'_org_add_user_verify_otp')
        return res, 200
    except Exception as e:
        logarray.update({STATUS: ERROR, RESPONSE: str(e)})
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400


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
        post_data['updated_on'] = datetime.datetime.now().strftime(D_FORMAT)
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
        post_data['updated_on'] = datetime.datetime.now().strftime(D_FORMAT)
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
        post_data['updated_on'] = datetime.datetime.now().strftime(D_FORMAT)
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
        post_data['updated_on'] = datetime.datetime.now().strftime(D_FORMAT)
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
    
@bp.route('/get_user_access_requests', methods=['GET'])
def get_user_access_requests():
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
                data.append({
                'rule_name' : Roles.rule_id(d.get('rule_id', 0)).get('rule_name', '').title() ,# type: ignore
                'access_id' : d.get('transaction_id',''),
                'dept_name' : d.get('dept_id',''),
                'designation' : d.get('designation',''),
                'digilockerid' : "NA",
                'is_active' : d.get('request_status',''),
                'is_loggedin' : d.get('dept_id',''),
                'rule_desc' : "NA",
                'sec_name' : "NA",
                'updated_by' : d.get('updated_by',''),
                'org_id' : d.get('org_id',''),
                'updated_on' : d.get('updated_on',''),
                'profile' : {
                    "email" : d.get('email',''),
                    "gender":"NA",
                    "mobile": d.get('mobile',''),
                    "photo": "NA",
                    "username": d.get('email','')
                }
                
                })
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
        # post_data['is_active'] = "N"
        # res1, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_users_pool"], post_data)
        # if status_code != 200:
        #     logarray.update({RESPONSE: res1})
        #     RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, g.endpoint)
        #     return res1, status_code
        # post_data['is_active'] = "Y"
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
    
