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
from lib.commonlib_auth import CommonLib
import requests
from api.org_activity import activity_insert
import os
import configparser
import hashlib
from lib import otp_service
from lib.drivejwt_auth import DriveJwt
otp_connector = otp_service.OTP_services()

get_ttl = configparser.ConfigParser()
get_ttl.read('lib/cache_ttl.ini')

VALIDATIONS = Validations()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQLOGS = RabbitMQLogs()
REDISLIB = RedisLib()
ELASTICLIB = ElasticLib()

accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']
ORGLIB = OrgLib()

bp = Blueprint('section', __name__)
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
        g.user_sections = jwtlib.user_sections
        g.org_access_functions = jwtlib.org_access_functions
        g.org_ds_fn_roles = jwtlib.org_ds_fn_roles
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
            
        logarray.update({'org_id': g.org_id, 'digilockerid': g.digilockerid})
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#12900]"}, 401

@staticmethod
def ds_fn_roles(act,access_id):
    try:

        if g.role == "ORGR001":
            return {STATUS: SUCCESS}, 200
        elif g.role == "ORGR003":
            for b in g.org_access_rules:
                access_id1 = hashlib.md5((g.org_id+g.digilockerid+g.org_id).encode()).hexdigest()
                if access_id1 == b.get('access_id') and b.get('rule_id') != "ORGR002" and b.get('is_active') == "Y" and b.get('user_type'):
                    return {STATUS: SUCCESS}, 200

                if access_id == b.get('access_id') and b.get('rule_id') != "ORGR002" and b.get('is_active') == "Y":
                    return {STATUS: SUCCESS}, 200
            return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400
        elif g.role == "ORGR002":
            for b in g.org_access_rules:
                if access_id == b.get('access_id') and b.get('rule_id') != "ORGR002" and b.get('is_active') == "Y":
                    return {STATUS: SUCCESS}, 200
            return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400
        return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + act }, 400 
        
        # if access_id not in [a['access_id'] for a in g.org_ds_fn_roles]:
        #     return {STATUS: ERROR, ERROR_DES: "You do not have permission to " + fn_id['fn_description'] }, 400
        # return {STATUS: SUCCESS}, 200
        
    except Exception as e:
        print({STATUS: ERROR, ERROR_DES: str(e)})
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "Failed to verify user permission."}, 400

@bp.route('/get', methods=['POST'])
def get():
    try:
        
        res, status_code = VALIDATIONS.section_department_org_details(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        data ={
            "org_id":  g.org_id,
            "dept_id":  access_post_data['dept_id']
        }
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], data, {"name":1,"description":1,"created_by":1,"updated_on":1,"is_active":1},limit=1)
        logarray.update({RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        if status_code == 400:
            return {STATUS: ERROR, ERROR_DES: "No Record Found."}, 401
        if status_code != 200 or type(resp[RESPONSE]) != type([]):
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164')}, 401
        des =  resp['response']
        return {STATUS: SUCCESS, RESPONSE: des}, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400

    
@bp.route('/list', methods=['POST'])
def list_section():
    try:
        did = request.form.get('dept_id')
        res = REDISLIB.get(g.org_id +'_'+did+'_dept_structure') 
        if res:
            res = json.loads(res)
            return {STATUS: SUCCESS, RESPONSE: res}, 200
        
        res, status_code = VALIDATIONS.section_department_org_details(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        data ={
            "org_id":  g.org_id,
            "dept_id":  access_post_data['dept_id']
        }
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], data, {"name":1,"sec_id":1,"created_by":1,"updated_on":1,"is_active":1},limit=500)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        data = []

        for d in resp[RESPONSE]:
            count = 0
            for rule in g.org_access_rules:
            # Check if dept_id matches and sec_id exists but rule_id is None
                if d.get('sec_id') == rule.get('sec_id') and access_post_data['dept_id'] == rule.get('dept_id') and rule.get('rule_id'):
                    count += 1
                count = count
            if g.role == "ORGR001":
                profile_details = CommonLib.get_profile_details({'digilockerid': d['created_by']})
                d.update(profile_details)
                d['count'] = count
                data.append(d)
            else:
                if d['sec_id'] in g.user_sections:
                    profile_details = CommonLib.get_profile_details({'digilockerid': d['created_by']})
                    d.update(profile_details)
                    d['count'] = count
                    data.append(d)

            # if d['dept_id'] not in g.user_departments:
            #     res[RESPONSE].pop(d)
                
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/get_users', methods=['POST'])
def get_users():
    try:
        
        res, status_code = VALIDATIONS.section_users(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        data =[]
        for a in g.org_access_rules:
            if a.get('rule_id') != None and a.get('sec_id') == access_post_data['sec_id'] : 
                data.append({
                    "digilockerid": a['digilockerid'],
                    "is_active": a['is_active'],
                    "role_name": Roles.rule_id(a['rule_id']).get("rule_name"),
                    **CommonLib.get_profile_details({'digilockerid': a['digilockerid']})

                })
        return {STATUS: SUCCESS, RESPONSE: data}, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/get_users_count', methods=['POST'])
def get_users_count():
    try:
        
        res, status_code = VALIDATIONS.section_users(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        count=0
        for a in g.org_access_rules:
            if a.get('rule_id') != None and a.get('sec_id') == access_post_data['sec_id'] and a.get('dept_id') == access_post_data['dept_id'] :
              count = count+1  
        count= count
        return {STATUS: SUCCESS, RESPONSE: count}, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400

@bp.route('/section_count', methods=['POST'])
def section_count():
    try:
        count=0
        for a in g.user_sections:
            count = count+1
        count= count
        return {STATUS: SUCCESS, RESPONSE: count}, 200
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_dept_count: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400

@bp.route('/get_sec_count', methods=['POST'])
def get_dept_count():
    try:
        
        res, status_code = VALIDATIONS.section_count(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        count = 0
        for rule in g.org_access_rules:
            if access_post_data['dept_id'] == rule.get('dept_id') and rule.get('sec_id') and rule.get('rule_id') is None:
                count += 1
        count = count

        return {STATUS: SUCCESS, RESPONSE: count}, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/list_users', methods=['POST'])
def list_users():
    try:
        res, status_code = VALIDATIONS.section_users(request)
        if status_code != 200:
          return res, status_code
        dept_id = res['access_post_data']['dept_id']
        sec_id = res['access_post_data']['sec_id']
        
        
        data = []
        for d in g.org_access_rules:
            if (g.role == "ORGR001" or g.role == "ORGR003") and dept_id == d.get('dept_id') and sec_id == d.get('sec_id'):
                data.append({
                    "digilockerid": d['digilockerid'],
                    "is_active": d['is_active'],
                    "rule_name": Roles.rule_id(d['rule_id']).get("rule_name"),
                    **CommonLib.get_profile_details({'digilockerid': d['digilockerid']})

                })
            if g.role == "ORGR002" and dept_id == d.get('dept_id') and sec_id == d.get('sec_id') and g.digilockerid == d.get('digilockerid'):
                data.append({
                    "digilockerid": d['digilockerid'],
                    "is_active": d['is_active'],
                    "rule_name": Roles.rule_id(d['rule_id']).get("rule_name"),
                    **CommonLib.get_profile_details({'digilockerid': d['digilockerid']})

                })
                
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/update', methods=['POST'])
def update():
    try:
        res, status_code = VALIDATIONS.update_org_department_section(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']
        
        if access_post_data['sec_id'] == None:
           res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1371')}
           logarray.update({RESPONSE: res})
           RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
           return res, 400
         
        if g.org_id == None :
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        sec_id = access_post_data['sec_id']

        data = {
             
             "name":  access_post_data['name'],
             "description": access_post_data['description']
        }
        dept_sec_id = g.sec_details.get(sec_id,{}).get("dept_id","")
        act = 'update section'
        access_id = hashlib.md5((g.org_id+g.digilockerid+dept_sec_id+sec_id).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code

        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_sec"], data, sec_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        sec_name = g.sec_details.get(access_post_data['sec_id'],{}).get("name","")
        dept_name = g.dept_details.get(dept_sec_id,'').get("name","")
        activity_insert("update_section","update_section",g.digilockerid,g.org_id,sec_name,'','',dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+dept_sec_id+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+dept_sec_id+ '_dept_structure')
        
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400


@bp.route('/create', methods=['POST'])
def create():
    try:
        dept_id = request.form.get('dept_id') 
        # To validate Section limit Exceeded or not 
        max_limit = int(CONFIG["max_section_limit"]["limit"])
        num_section = VALIDATIONS.validate_limit_section(dept_id)
        if max_limit <= num_section:
            res = {STATUS: "error", ERROR_DES: "Number of Section Limit Exceeded."}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        
        res,status_code = VALIDATIONS.create_org_department_section(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']
        
        # To validate section name Exist or not 
        sec_flag = VALIDATIONS.validate_name(access_post_data["name"],'section')
        if sec_flag:
            res = {STATUS: "error", ERROR_DES: "This name of Section already exist"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        
        if access_post_data['dept_id'] == None and access_post_data['sec_id'] == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1361')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        if g.org_id == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        if g.digilockerid == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_104')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        data = {
             "org_id": g.org_id,
             "dept_id": access_post_data['dept_id'],
             "sec_id": access_post_data['sec_id'],
             "name":  access_post_data['name'],
             "is_active": "Y",
             "created_by": g.digilockerid,
             "updated_on": datetime.now().strftime(D_FORMAT),
             "description": access_post_data['description']
             
        }
        act = 'create section'
        access_id = hashlib.md5((g.org_id+g.digilockerid+access_post_data['dept_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        
        path = access_post_data['dept_id'] + "/" + access_post_data['sec_id']
        url = CONFIG['org_drive_api']['url'] + "/" + 'upload'
        
        headers = {
            'device-security-id': g.did,
            'Authorization': 'Bearer '+ g.jwt_token,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.request("POST", url, headers=headers, data={'path': path})
        try:
            api_res, status_code = json.loads(response.text), response.status_code
        except Exception:
            print(response.text)
            api_res, status_code = {'status': 'error', 'msg': "Failed to create folder for Section."}
        if status_code not in [200,201]:
            logarray.update({RESPONSE: api_res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return api_res, status_code
        
        resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_sec"], data)
        if status_code != 200:
            logarray.update({RESPONSE: resd})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resd, status_code
        
        #updated by subhash/bhavish
        dept_name = g.dept_details.get(access_post_data['dept_id'],{}).get("name","")
        url = CONFIG['org_drive_api']['url'] + "/" + 'upload'
        payload = {
            'path': path,
        }
        headers = {
        'device-security-id': g.did,
        'Authorization': 'Bearer '+ g.jwt_token,
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        requests.request("POST", url, headers=headers, data=payload)
        activity_insert("create_section","create_section",g.digilockerid,g.org_id,access_post_data['name'],'','',dept_name)
        post_data= {
        'org_id': g.org_id,
        'digilockerid': g.digilockerid,
        'rule_id': g.role,
        'dept_id': access_post_data['dept_id'],
        'sec_id': access_post_data['sec_id'],
        'is_active': "Y",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': hashlib.md5((g.org_id+g.digilockerid+access_post_data['dept_id']+access_post_data['sec_id']).encode()).hexdigest()
        }
        
        rules_res, status_code1 = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], post_data)
        if status_code != 200:
            logarray.update({RESPONSE: rules_res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return rules_res, status_code1
        activity_insert("access_section","access_section",g.digilockerid,g.org_id,access_post_data['name'],'','',dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+access_post_data['dept_id']+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+access_post_data['dept_id']+ '_dept_structure')
        
        return rules_res, status_code1
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "create_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/assign', methods=['POST'])
def assign():
    try:
        form_data = request.form
        dept_id = form_data.get('dept_id')
        sec_id = form_data.get('sec_id')
        digilockerid = form_data.get('digilockerid')

        # To check how many section can be add with a user  
        num_section = VALIDATIONS.find_sections_for_user(g.org_access_rules, digilockerid, dept_id)
        max_user_limit_section = int(CONFIG["max_user_limit_section"]["limit"])
    
        if max_user_limit_section <= num_section:
            res = {STATUS: "error", ERROR_DES: f"A user can't be added more then {max_user_limit_section} Sections"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        
        # To check how many user can be add with a section  
        num_user = VALIDATIONS.max_user_count_sections(g.org_access_rules, dept_id, sec_id)
        max_user_limit_section = int(CONFIG["max_user_limit_section"]["limit"])
        
        if max_user_limit_section <= num_user:
            res = {STATUS: "error", ERROR_DES: f"You can't more then {max_user_limit_section} user to a sections"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        

        res, status_code = VALIDATIONS.assign_users_org_section(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        
        act = 'assign section'
        access_id = hashlib.md5((g.org_id+g.digilockerid+res['post_data']['dept_id']+res['post_data']['sec_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        
        resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], res['post_data'])
        if status_code != 200:
            logarray.update({RESPONSE: resd})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resd, status_code
        post_data = res['post_data']
        rule_name = Roles.rule_id(post_data['rule_id']).get('rule_name')
        dept_name = g.dept_details.get(post_data['dept_id'],{}).get("name","")
        sec_name = g.sec_details.get(post_data['sec_id'],{}).get("name","")
        activity_insert("assign_section","assign_section",g.digilockerid,g.org_id,sec_name,rule_name,post_data['digilockerid'],dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+post_data['dept_id']+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+post_data['dept_id']+ '_dept_structure')
            
        return resd, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "assign_section: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/role_update', methods=['POST'])
def role_update():
    try:
        
        res,status_code = VALIDATIONS.update_role_users_org_section(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        post_data = res['post_data']
        sec_access_id = post_data.pop('access_id',None)

        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, sec_access_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        rule_name = Roles.rule_id(post_data['rule_id']).get('rule_name')
        dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
        sec_name = g.sec_details.get(res['sec_id'],{}).get("name","")
        activity_insert("role_section","role_section",g.digilockerid,g.org_id,sec_name,rule_name,res['digilockerid'],dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+res['dept_id']+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+res['dept_id']+ '_dept_structure')
            
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
@bp.route('/revoke', methods=['POST'])
def revoke():
    try:
        
        res,status_code = VALIDATIONS.revoke_users_org_section(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        sec_access_id = res['post_data'].pop('access_id',None)

        act = 'revoke section'
        access_id = hashlib.md5((g.org_id+g.digilockerid+res['dept_id']+res['sec_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        
        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], res['post_data'], sec_access_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        
        dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
        sec_name = g.sec_details.get(res['sec_id'],{}).get("name","")
        activity_insert("revoke_section","revoke_section",g.digilockerid,g.org_id,sec_name,'',res['digilockerid'],dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+res['dept_id']+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+res['dept_id']+ '_dept_structure')
        
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/active', methods=['POST'])
def active():
    try:
        
        res,status_code = VALIDATIONS.active_users_org_section(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        for post_data in res['post_data']:
            access_id = post_data.pop('access_id',None)

            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code
            
            dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
            sec_name = g.sec_details.get(res['sec_id'],{}).get("name","")
            if access_id == hashlib.md5((g.org_id+res['digilockerid']+res['dept_id']).encode()).hexdigest():
                activity_insert("active_department","active_department",g.digilockerid,g.org_id,dept_name,'',res['digilockerid'],'')
            activity_insert("active_section","active_section",g.digilockerid,g.org_id,sec_name,'',res['digilockerid'],dept_name)
        
        # Remove old department redis data to create new department list redis
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+res['dept_id']+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+res['dept_id']+ '_dept_structure')
            
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "active_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/n_active', methods=['POST'])
def n_active():
    try:
        res, status_code = VALIDATIONS.inactive_org_department_section(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']

        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
         
        if g.org_id == None :
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        dept_sec_id = None
        for access_post in access_post_data:
            sec_id = access_post.pop("sec_id", None)
            access_id = access_post.pop("access_id", None)
            access_post["created_by"] = g.digilockerid
            dept_sec_id = g.sec_details.get(sec_id, {}).get("dept_id", "")

            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_sec"], access_post, sec_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code

            post_data1 = {
                'is_active': "N",
                'updated_by': g.digilockerid,
                'updated_on': datetime.now().strftime(D_FORMAT)
            }

            rules_res, status_code1 = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data1, access_id)
            if status_code1 != 200:
                logarray.update({RESPONSE: rules_res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return rules_res, status_code1

            access_post["access_id"] = access_id
            access_post["sec_id"] = sec_id
        
        sec_name = g.sec_details.get(sec_id, {}).get("name", "")
        dept_name = g.dept_details.get(dept_sec_id, {}).get("name", "")
        activity_insert("inactive_section", "inactive_section", g.digilockerid, g.org_id, sec_name, '', '', dept_name)
        
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+dept_sec_id+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+dept_sec_id+ '_dept_structure')
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "inactive_section: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/y_active', methods=['POST'])
def y_active():
    try:
        res, status_code = VALIDATIONS.inactive_to_active_org_department_section(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']

        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
         
        if g.org_id == None :
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        dept_sec_id = None
        for access_post in access_post_data:
            sec_id = access_post.pop("sec_id", None)
            access_id = access_post.pop("access_id", None)
            access_post["created_by"] = g.digilockerid
            
            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_sec"], access_post, sec_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code

            post_data1 = {
                'is_active': "Y",
                'updated_by': g.digilockerid,
                'updated_on': datetime.now().strftime(D_FORMAT)
            }

            rules_res, status_code1 = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data1, access_id)
            if status_code1 != 200:
                logarray.update({RESPONSE: rules_res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return rules_res, status_code1

            access_post["access_id"] = access_id
            access_post["sec_id"] = sec_id
            dept_sec_id = g.sec_details.get(sec_id, {}).get("dept_id", "")
        sec_name = g.sec_details.get(sec_id, {}).get("name", "")
        dept_name = g.dept_details.get(dept_sec_id, {}).get("name", "")
        activity_insert("inactive_section", "inactive_section", g.digilockerid, g.org_id, sec_name, '', '', dept_name)
        res_org = REDISLIB.get(g.org_id + '_org_structure')  
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        # Remove old department redis data to create new department list redis  
        res_dept = REDISLIB.get(g.org_id+'_'+dept_sec_id+ '_dept_structure') 
        if res_dept:
            REDISLIB.remove(g.org_id+'_'+dept_sec_id+ '_dept_structure')
        
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "inactive_section: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
