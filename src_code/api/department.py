''' Departments BP Controller'''
from flask import request, Blueprint, g,json
import requests
from lib.constants_auth import *
from lib.validations_auth import Validations
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.rabbitmqlogs import RabbitMQLogs
from lib.redislib import RedisLib
from lib.orglib import OrgLib
from lib.elasticlib import ElasticLib
from api.section import list_section
from api.org_activity import activity_insert
import os
import configparser
import hashlib
from lib import otp_service
import uuid
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

bp = Blueprint('department', __name__)
logarray = {}

@bp.before_request
def validate_user():
    ''' JWT Authentication '''
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
        g.org_access_functions = jwtlib.org_access_functions
        g.user_departments = jwtlib.user_departments
        g.org_access_functions = jwtlib.org_access_functions
        g.org_ds_fn_roles = jwtlib.org_ds_fn_roles
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
        logarray.update({'org_id': g.org_id, 'digilockerid': g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401

@staticmethod
def ds_fn_roles(act, access_id):
    ''' fn roles '''
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

    except Exception as e:
        print({STATUS: ERROR, ERROR_DES: str(e)})
        return {STATUS: ERROR, ERROR_DES: "Failed to verify user permission."}, 400

@bp.route('/get', methods=['POST'])
def get():
    ''' get departments '''
    try:
        res, status_code = VALIDATIONS.section_department_org_details(request)
        if status_code != 200:
          return res, status_code
        access_post_data = res['access_post_data']
        data ={
            "dept_id":  access_post_data['dept_id']
        }
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"],
                                             data,
                                             {"name":1,"description":1,"created_by":1,"updated_on":1,"is_active":1})
        logarray.update({RESPONSE: resp})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        des = resp[RESPONSE][0]
        res, code = list_section()
        secs = []
        if code == 200:
            secs = res[RESPONSE]
        return {STATUS: SUCCESS, RESPONSE: {**des, "sections": secs}}, status_code

    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/get_users', methods=['POST'])
def get_users():
    ''' get users '''
    try:
        res, status_code = VALIDATIONS.department_get_users(request)
        if status_code != 200:
          return res, status_code
        data =[]
        for a in g.org_access_rules:
            if a.get('rule_id') != None and not a.get('sec_id') and a.get('dept_id') == res['dept_id'] :
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
        return res, 400
@bp.route('/get_users_count', methods=['POST'])
def get_users_count():
    ''' get users counts '''
    try:
        res, status_code = VALIDATIONS.department_get_users(request)
        if status_code != 200:
          return res, status_code
        count=0
        for a in g.org_access_rules:
            if a.get('rule_id') != None and not a.get('sec_id') and a.get('dept_id') == res['dept_id'] :
              count = count+1
        count= count
        return {STATUS: SUCCESS, RESPONSE: count}, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_users_count: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/get_dept_count', methods=['POST'])
def get_dept_count():
    ''' get dept count '''
    try:
        count = 0
        for a in g.dept_details:
            if a:
                count = count+1
        count= count
        return {STATUS: SUCCESS, RESPONSE: count}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_dept_count: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/get_dept_list', methods=['POST'])
def get_dept_list():
    ''' list departments '''
    listfull = list_department()
    api_res, status_code = listfull
    if api_res.get('status') == 'success':
        departments = api_res.get('response', [])
        dept_list = []
        for department in departments:
            dept_id = department.get('dept_id')
            name = department.get('name')
            dept_list.append({'dept_id': dept_id, 'name': name})
        # dept_list.append({'dept_id': g.org_id, 'name': "Default"})

        return {STATUS: SUCCESS, RESPONSE: dept_list}, status_code
    else:
        return []

@bp.route('/list', methods=['POST'])
def list_department():
    ''' list departments '''
    try:
        res = REDISLIB.get(g.org_id + '_org_structure')
        if res:
            res = json.loads(res)
            return {STATUS: SUCCESS, RESPONSE: res}, 200
        resp, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"],
                                             {'org_id':g.org_id}, {"name":1,"dept_id":1,"created_by":1,
                                                                   "updated_on":1,"is_active":1},limit=500)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        data = []
        for d in resp[RESPONSE]:
            count = 0
            for rule in g.org_access_rules:
                if d.get('dept_id') == rule.get('dept_id'):
                    count += 1
                count = count
            if g.role == "ORGR001":
                d['count'] = count
                data.append({**d,**CommonLib.get_profile_details({'digilockerid': d['created_by']})})
            else:
                if d['dept_id'] in g.user_departments:
                    d['count'] = count
                    data.append(d | CommonLib.get_profile_details({'digilockerid': d['created_by']}))
        data.append({"org_id":g.org_id, "name":"Default",
                     "dept_id": g.org_id, "name": "Default","is_active": "Y",
                     "created_by": "NA","count": "NA","count_sec": "NA",
                     "description": "Default Department of Organization","photo": "NA","updated_on": "NA",
                     "username": "NA","sections": "NA"})
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/list_users', methods=['POST'])
def list_users():
    ''' list users '''
    try:
        res, status_code = VALIDATIONS.department_users(request)
        if status_code != 200:
          return res, status_code
        dept_id = res['access_post_data']['dept_id']
        data = []
        for d in g.org_access_rules:
            if (g.role == "ORGR001" or g.role == "ORGR003") and dept_id == d.get('dept_id') and not d.get('sec_id'):
                data.append({
                    "dept_id": d.get('dept_id'),
                    "digilockerid": d['digilockerid'],
                    "is_active": d['is_active'],
                    "rule_name": Roles.rule_id(d['rule_id']).get("rule_name"),
                    **CommonLib.get_profile_details({'digilockerid': d['digilockerid']})

                })
            
            if  dept_id == d.get('org_id') and d.get('user_type') and not d.get('dept_id') and not d.get('sec_id'):
                data.append({
                    "dept_id": d.get('dept_id'),
                    "digilockerid": d['digilockerid'],
                    "is_active": d['is_active'],
                    "rule_name": Roles.rule_id(d['rule_id']).get("rule_name"),
                    "user_type": d.get('user_type'),
                    **CommonLib.get_profile_details({'digilockerid': d['digilockerid']})

                })

            if g.role == "ORGR002" and dept_id == d.get('dept_id') and not d.get('sec_id') and g.digilockerid == d.get('digilockerid'):
                data.append({
                    "dept_id": d.get('dept_id'),
                    "digilockerid": d['digilockerid'],
                    "is_active": d['is_active'],
                    "rule_name": Roles.rule_id(d['rule_id']).get("rule_name")
                    **CommonLib.get_profile_details({'digilockerid': d['digilockerid']})

                })
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/update', methods=['POST'])
def update():
    ''' updated deparments '''
    try:
        res,status_code = VALIDATIONS.update_org_depart(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']

        if access_post_data['dept_id'] == None:
           res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1351')}
           logarray.update({RESPONSE: res})
           RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
           return res, 400
        if g.org_id == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        data = {
             "name":  access_post_data['name'],
             "description": access_post_data['description']
        }

        act = 'update department'
        access_id = hashlib.md5((g.org_id+g.digilockerid+access_post_data['dept_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code

        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_dept"],
                                                    data, access_post_data['dept_id'])
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        activity_insert("update_department","update_department",g.digilockerid,g.org_id,
                        access_post_data['name'],'','','')
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400


@bp.route('/create', methods=['POST'])
def create():
    ''' create departments '''
    try:
        res, status_code = VALIDATIONS.create_org_department(request)
        if status_code != 200:
            return res, status_code
        access_post_data = res['access_post_data']
        dept_flag = VALIDATIONS.validate_name(access_post_data["name"])
        if dept_flag:
            res = {STATUS: "error", ERROR_DES: "This name of department already exist..!"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        max_dept_limit = int(CONFIG["max_department_limit"]["limit"])
        num_dept = VALIDATIONS.validate_limit_dept()
        if max_dept_limit <= num_dept:
            res = {STATUS: "error", ERROR_DES: f"You can't added more then {max_dept_limit}. Departments...!"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        if access_post_data['dept_id'] == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1351')}
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
             "name":  access_post_data['name'],
             "is_active": "Y",
             "created_by": g.digilockerid,
             "updated_on": datetime.now().strftime(D_FORMAT),
             "description": access_post_data['description']
        }

        act = 'create department'
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code

        path =  access_post_data['dept_id']
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
            api_res, status_code = {'status': 'error', 'msg': "Failed to create folder for Department."}
        if status_code not in [200,201]:
            logarray.update({RESPONSE: api_res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return api_res, status_code

        resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_dept"], data)
        if status_code != 200:
            logarray.update({RESPONSE: resd})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resd, status_code

        activity_insert("create_department","create_department",
                        g.digilockerid,g.org_id,access_post_data['name'],'','','')
        post_data= {
        'org_id': g.org_id,
        'digilockerid': g.digilockerid,
        'rule_id': g.role,
        'dept_id': access_post_data['dept_id'],
        'is_active': "Y",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': hashlib.md5((g.org_id+g.digilockerid+access_post_data['dept_id']).encode()).hexdigest()
        }
        rules_res, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], post_data)
        if status_code != 200:
            logarray.update({RESPONSE: rules_res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return rules_res, status_code
        activity_insert("access_department","access_department",g.digilockerid,
                        g.org_id,access_post_data['name'],'','','')
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return rules_res, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "create_details: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/assign', methods=['POST'])
def assign():
    ''' assign users departments '''
    try:
        form_data = request.form
        dept_id = form_data.get('dept_id')
        digilockerid = form_data.get('digilockerid')
        num_dept = VALIDATIONS.find_departments_for_user(g.org_access_rules, dept_id)
        max_user_limit = int(CONFIG["max_user_limit_department"]["limit"])
        if max_user_limit <= num_dept:
            res = {STATUS: "error", ERROR_DES: f"You can't add more then {max_user_limit} department with a User!"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        num_user = VALIDATIONS.max_user_count_department(g.org_access_rules, digilockerid)
        max_department_limit = int(CONFIG["max_user_limit_department"]["limit"])
        if max_department_limit <= num_user:
            res = {STATUS: "error", ERROR_DES: f"You can't added more then {max_department_limit} User in a department"}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, "Logstash_Xchange", "org_logs_")
            return res, 400
        res, status_code = VALIDATIONS.assign_users_org_details(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        act = 'department assign'
        access_id = hashlib.md5((g.org_id+g.digilockerid+res['dept_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        resd, status_code = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_rules"], res)
        if status_code != 200:
            logarray.update({RESPONSE: resd})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resd, status_code
        digilockerid = res.pop("digilockerid", None)
        updated_by = res.pop("updated_by", None)
        resp, status_code1 = MONGOLIB.org_eve_post(CONFIG["org_eve"]["collection_fu_roles"], res)
        if status_code1 != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code1
        if digilockerid is not None:
            res["digilockerid"] = digilockerid
        if updated_by is not None:
            res["updated_by"] = updated_by
        rule_name = Roles.rule_id(res['rule_id']).get('rule_name')
        dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
        activity_insert("department_assign","department_assign",g.digilockerid,g.org_id,
                        dept_name,rule_name,res['digilockerid'],'')
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resd, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "assign_department: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/role_update', methods=['POST'])
def role_update():
    ''' update roles '''
    try:
        res, status_code = VALIDATIONS.update_assign_users_org_details(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        for post_data in res['post_data']:
            access_id = post_data.pop('access_id',None)
            resd, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id)
            if status_code != 200:
                logarray.update({RESPONSE: resd})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resd, status_code
            rule_name = Roles.rule_id(post_data['rule_id']).get('rule_name')
            dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
            activity_insert("role_department","role_department",g.digilockerid,
                            g.org_id,dept_name,rule_name,res['digilockerid'],'')
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resd, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "assign_department: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/revoke', methods=['POST'])
def revoke():
    ''' revoke access '''
    try:
        res,status_code = VALIDATIONS.revoke_assign_users_org_details(request)
        if status_code != 200:
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        act = 'revoke department'
        access_id1 = hashlib.md5((g.org_id+g.digilockerid+res['dept_id']).encode()).hexdigest()
        result, status_code = ds_fn_roles(act,access_id1)
        if status_code != 200:
            logarray.update({RESPONSE: result})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return result, status_code
        for post_data in res['post_data']:
            access_id = post_data.pop('access_id',None)
            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code
            dept_name = g.dept_details.get(res['dept_id'],{}).get("name","")
            if post_data.get('sec_id'):
                sec_name = g.sec_details.get(post_data.get('sec_id'),{}).get("name","")
                activity_insert("revoke_section","revoke_section",
                                g.digilockerid,g.org_id,sec_name,'',res['digilockerid'],dept_name)
            activity_insert("revoke_department","revoke_department",g.digilockerid,g.org_id,
                            dept_name,'',res['digilockerid'],'')
            res_org = REDISLIB.get(g.org_id + '_org_structure')
            if res_org:
                REDISLIB.remove(g.org_id + '_org_structure')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "update_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/active', methods=['POST'])
def active():
    ''' active department'''
    try:
        res,status_code = VALIDATIONS.active_assign_users_org_details(request)
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
            activity_insert("active_department","active_department",g.digilockerid,
                            g.org_id,dept_name,'',res['digilockerid'],'')
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "active_details: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/n_active', methods=['POST'])
def n_active():
    ''' inactive '''
    try:
        res, status_code = VALIDATIONS.inactive_org_department_view(request)
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
        for access_post in access_post_data:
            dept_id = access_post.pop("dept_id", None)
            access_id = access_post.pop("access_id", None)
            access_post["created_by"] = g.digilockerid

            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_dept"], access_post, dept_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code
            post_data1 = {
            'is_active': "N",
            'updated_by': g.digilockerid,
            'updated_on': datetime.now().strftime(D_FORMAT)
            }
            rules_res, status_code1 = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"],
                                                              post_data1, access_id)
            if status_code != 200:
                logarray.update({RESPONSE: rules_res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return rules_res, status_code1
            access_post["access_id"] = access_id
            access_post["dept_id"] = dept_id
        dept_name = g.dept_details.get(dept_id,'').get("name","")
        activity_insert("inactive_department","inactive_section",g.digilockerid,g.org_id,'','','',dept_name)
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "inactive_department: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400

@bp.route('/y_active', methods=['POST'])
def y_active():
    ''' active '''
    try:
        res, status_code = VALIDATIONS.inactive_to_active_org_department_view(request)
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
        for access_post in access_post_data:
            dept_id = access_post.pop("dept_id", None)
            access_id = access_post.pop("access_id", None)
            access_post["created_by"] = g.digilockerid

            resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_dept"], access_post, dept_id)
            if status_code != 200:
                logarray.update({RESPONSE: resp})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return resp, status_code
            post_data= {
            'is_active': "Y",
            'updated_by': g.digilockerid,
            'updated_on': datetime.now().strftime(D_FORMAT)
            }
            rules_res, status_code1 = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"],
                                                              post_data, access_id)
            if status_code != 200:
                logarray.update({RESPONSE: rules_res})
                RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return rules_res, status_code1
            access_post["access_id"] = access_id
            access_post["dept_id"] = dept_id
        dept_name = g.dept_details.get(dept_id,'').get("name","")
        activity_insert("activate_department","inactive_section",g.digilockerid,g.org_id,'','','',dept_name)
        res_org = REDISLIB.get(g.org_id + '_org_structure')
        if res_org:
            REDISLIB.remove(g.org_id + '_org_structure')
        return resp, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "inactive_department: " + str(e)}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return res, 400
