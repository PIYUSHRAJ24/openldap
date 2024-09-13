import hashlib
from flask import request, Blueprint, g
from lib.constants_auth import *
from lib.rabbitmqlogs import RabbitMQLogs
from lib.commonlib_auth import CommonLib
from lib.drivejwt_auth import DriveJwt
from lib.validations_auth import Validations
from lib.mongolib import MongoLib
from api.org_activity import activity_insert

RABBITMQLOGS = RabbitMQLogs()
VALIDATIONS = Validations()
MONGOLIB = MongoLib()
accounts_eve = CONFIG['accounts_eve']
org_eve = CONFIG['org_eve']

bp = Blueprint('users', __name__)
logarray = {}


@bp.before_request
def validate_user():
    """
        HMAC Authentication
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
        g.pool_users_details = jwtlib.pool_users_details
        g.org_user_details = jwtlib.org_user_details
        g.user_rules = jwtlib.user_rules
        g.user_departments = jwtlib.user_departments
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
        logarray.update({'org_id': g.org_id, 'digilockerid': g.digilockerid})
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13100]"}, 401

@bp.route('/get', methods=['GET'])
def get_users():
    try:
        data =[]
        for a in g.org_access_rules:
            if a.get('rule_id') != None and a.get('rule_id') != 'ORGR001' and not a.get('sec_id') and not a.get('dept_id') and a.get('is_active') == "Y" and not a.get('user_type'):
                data.append({
                    "access_id" : a['access_id'],
                    "digilockerid": a['digilockerid'],
                    "username" : CommonLib.get_profile_details({'digilockerid': a['digilockerid']}).get('username','')

                })
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "get_role: " + str(e)}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/users_count', methods=['GET'])
def users_count():
    try:
        count = 0
        for a in g.org_access_rules:
            if a.get('rule_id') != None and not a.get('sec_id') and not a.get('dept_id'):
                count = count+1  
        count= count
        return {STATUS: SUCCESS, RESPONSE: count}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13101]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/users_pool_list', methods=['GET'])
def users_pool_list():
    try:
        data =[]
        for a in g.pool_users_details:
            if g.role == 'ORGR001':
                data.append({
                    "is_active": a.get('is_active',''),
                    "access_id" : a.get('access_id',''),
                    "rule_id": a.get("rule_id",''),
                    "digilockerid": a.get('digilockerid',''),
                    "updated_by": a.get('updated_by',''),
                    "updated_on": a.get('updated_on',''),
                    "username" : CommonLib.get_profile_details({'digilockerid': a.get('digilockerid','')}).get('username','')
                })
            else:
                data.append({
                    "is_active": a.get('is_active',''),
                    "access_id" : a.get('access_id',''),
                    "rule_id": a.get("rule_id",''),
                    "digilockerid": a.get('digilockerid',''),
                    "updated_by": a.get('updated_by',''),
                    "updated_on": a.get('updated_on',''),
                    "username" : CommonLib.get_profile_details({'digilockerid': a.get('digilockerid','')}).get('username','')
                })
            
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13102]"}
        logarray.update({RESPONSE: res})
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/verified', methods=['POST'])
def verified():
    try:
        
        res,status_code = VALIDATIONS.access_id_pool_user(request)
        if status_code != 200:
            return res, status_code
        
        access_id = res['access_id']

        if g.org_id == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        for a in g.pool_users_details:
            if a.get("access_id") == access_id and a.get('is_active') == "N":
                data = {
                    "is_active":"Y",
                    "updated_on" : datetime.now().strftime(D_FORMAT),
                    "updated_by" : g.digilockerid
                }
                resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_users_pool"], data, access_id)
                if status_code != 200:
                    logarray.update({RESPONSE: resp})
                    RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return resp, status_code
                username = CommonLib.get_profile_details({'digilockerid': a.get('digilockerid')}).get('username','')
                activity_insert("user_pool_verified","user_pool_verified",g.digilockerid,g.org_id,username,'','','')
                return resp, status_code
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1392')}, 400
            
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13103]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/deactivated', methods=['POST'])
def deactivated():
    try:
        
        res,status_code = VALIDATIONS.access_id_pool_user(request)
        if status_code != 200:
            return res, status_code
        
        access_id = res['access_id']

        if g.org_id == None:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        for a in g.pool_users_details:
            if a.get("access_id") == access_id and a.get('is_active') == "Y":
                data = {
                    "is_active":"N",
                    "updated_on" : datetime.now().strftime(D_FORMAT),
                    "updated_by" : g.digilockerid
                }
                resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_users_pool"], data, access_id)
                if status_code != 200:
                    logarray.update({RESPONSE: resp})
                    RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return resp, status_code
                username = CommonLib.get_profile_details({'digilockerid': a.get('digilockerid')}).get('username','')
                activity_insert("user_pool_deactivated","user_pool_deactivated",g.digilockerid,g.org_id,username,'','','')
                return resp, status_code
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_1393')}, 400
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13104]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/user_profile', methods=['POST'])
def user_profile():
    try:
        
        res,status_code = VALIDATIONS.org_user_profile_details(request)
        if status_code != 200:
            return res, status_code
        
        digilockerid = res['digilockerid']

        user_detail = CommonLib.get_profile_details({'digilockerid': digilockerid})
        data =[]
        for a in g.org_access_rules:
            
            if a.get("digilockerid") == digilockerid:
                if not a.get("dept_id") and not a.get("sec_id"):
                    user_detail['designation'] = Roles.rule_id(a.get('rule_id')).get('rule_name','')

                dept_name = g.dept_details.get(a.get("dept_id"), {}).get("name", "")
                sec_name = g.sec_details.get(a.get("sec_id"), {}).get("name", "")
                rule_name = Roles.rule_id(a.get("rule_id")).get('rule_name', "")
                data.append({
                    "dept_id": a.get("dept_id",''),
                    "digilockerid": a.get("digilockerid",''),
                    "dept_name": dept_name,
                    "sec_name": sec_name,
                    "role_name": rule_name,
                    "is_active": a.get("is_active")
                })
        return {STATUS: SUCCESS, RESPONSE: {"data": data,'user_profile': user_detail}}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13105]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/admin_access', methods=['POST'])
def admin_access():
    try:
        res,status_code = VALIDATIONS.org_admin_profile_details(request)
        if status_code != 200:
            return res, status_code
        
        digilockerid = res['digilockerid']
        post_data = {
            "rule_id": "ORGR001",
            "updated_by" : g.digilockerid,
            "updated_on" : datetime.now().strftime(D_FORMAT),
        }
        for a in g.org_access_rules:
            access_id = hashlib.md5((g.org_id+digilockerid).encode()).hexdigest()
            access_id_default = hashlib.md5((g.org_id+digilockerid+g.org_id).encode()).hexdigest()

            if a.get('access_id') == access_id and a.get('rule_id') == "ORGR001":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_220")}, 400
            elif a.get('access_id') == access_id_default and a.get('rule_id') == "ORGR001":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_220")}, 400

            if access_id_default == a.get('access_id') and a.get('user_type'):
                post_data["user_type"] = ""
                post_data["access_id"] = hashlib.md5((g.org_id+digilockerid).encode()).hexdigest()
                access_id_1 = a.get('access_id')
            elif access_id == a.get('access_id') and not a.get('user_type'):
                access_id_1 = access_id 
        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id_1)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        username = CommonLib.get_profile_details({'digilockerid': digilockerid}).get('username','')
        activity_insert("admin_access","admin_access",g.digilockerid,g.org_id,username,'','','')
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13106]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/default_user', methods=['POST'])
def default_user():
    try:
        
        res,status_code = VALIDATIONS.default_user_details(request)
        if status_code != 200:
            return res, status_code
        
        post_data = res['post_data'][0]
        access_id = post_data.pop('access_id1', None)
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        
        username = CommonLib.get_profile_details({'digilockerid': res['digilockerid']}).get('username','')
        activity_insert("default_users","default_users",g.digilockerid,g.org_id,username,'','','')
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13107]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
@bp.route('/default_remove', methods=['POST'])
def default_remove():
    try:
        
        res,status_code = VALIDATIONS.remove_default_user_details(request)
        if status_code != 200:
            return res, status_code
        
        post_data = res['post_data'][0]
        access_id = post_data.pop('access_id1', None)
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_119')}
            logarray.update({RESPONSE: res})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, 400
        resp, status_code = MONGOLIB.org_eve_update(CONFIG["org_eve"]["collection_rules"], post_data, access_id)
        if status_code != 200:
            logarray.update({RESPONSE: resp})
            RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return resp, status_code
        
        username = CommonLib.get_profile_details({'digilockerid': res['digilockerid']}).get('username','')
        activity_insert("default_users_remove","default_users_remove",g.digilockerid,g.org_id,username,'','','')
        return resp, status_code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#13108]"}
        logarray.update(res)
        RABBITMQLOGS.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        VALIDATIONS.log_exception(e)
        return res, 400
    
