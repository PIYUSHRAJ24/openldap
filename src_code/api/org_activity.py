from flask import request, Blueprint, g
from lib.redislib import RedisLib
from lib.commonlib import CommonLib
from lib.rabbitmq import RabbitMQ
from lib.validations import Validations
from lib.drivejwt import DriveJwt
from lib.constants import *
import time, json, requests, math
from datetime import datetime
from urllib.parse import unquote
from requests.utils import requote_uri
from requests.auth import HTTPBasicAuth
from lib.secretsmanager import SecretManager


VALIDATIONS = Validations()
REDISLIB = RedisLib()
RABBITMQ = RabbitMQ()

org_eve = CONFIG['org_eve']

CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local



bp = Blueprint('org_activity', __name__)
logarray = {}

@bp.before_request
def validate():
    """
        JWT Authentication
    """
    try:
        
        request_data = {
            'time_start': datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
        request.logger_data = request_data
        
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return

        if request.values.get('hmac'):
            res, status_code = CommonLib().validation_rules(request)
            if status_code != 200:
                return res, status_code
        else:
            jwtlib = DriveJwt(request, CONFIG)

            jwtres, status_code = jwtlib.jwt_login()

            if status_code == 200:
                g.path = jwtres
                g.jwt_token = jwtlib.jwt_token
                g.did = jwtlib.device_security_id
                g.digilockerid = jwtlib.digilockerid
                g.org_id = jwtlib.org_id
                if not g.org_id and not VALIDATIONS.is_valid_did(g.org_id):
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}, 401
                if not g.digilockerid and not VALIDATIONS.is_valid_did(g.digilockerid):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 401
            else:
                return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201') + '[#12700]'}, 401



@bp.route('/activity/send', methods=['POST'])
def activity_insert():
    try:
        '''to do hmac auth'''
        # ac_type, subject, user, org_id, doc_name="",role_id= "",user_affected="",subjectparams = ""
        user = request.values.get('user')
        ac_type = request.values.get('ac_type')
        subject = request.values.get('subject')
        org_id = request.values.get('org_id')
        doc_name = request.values.get('doc_name')
        role_id = request.values.get('role_id')
        user_affected = request.values.get('user_affected')
        subjectparams = request.values.get('subjectparams')
        res, code = activity_insert(ac_type, subject, user, org_id, doc_name,role_id,user_affected,subjectparams)
        return res, code
        
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201') + '[#12701]'}, 400

def activity_insert(ac_type, subject, user, org_id, doc_name="",role_id= "",user_affected="",subjectparams = ""):
    try:     
        now = datetime.now()   
        res, status_code = VALIDATIONS.activity_insert(ac_type,subject,user)
        if status_code == 400:
            return res, status_code
        ac_type = res['post_data']['type']
        subject = res['post_data']['subject']
        user = res['post_data']['user']  
        post_data = {
            "activity_id" : int(time.time()),
            "user" : user,
            "affecteduser" : org_id,
            "timestamp" : now,
            "type" : ac_type,
            "priority" : 40,
            "app" : "files",
            "subject" : subject,
            "subjectparams" : subjectparams,
            "message" : "",
            "messageparams" : "a:0:{M}",
            "file" : doc_name,
            "link" : "",
            "role_id": role_id,
            "user_affected": user_affected,
        }
        rmq_resp,status_code = RABBITMQ.send_to_queue({"data" :post_data}, 'Organization_Xchange','org_create_activity_')
        logarray.update({"request": res, "response": rmq_resp})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'acsapi_org_logs_')
        
        if status_code==200:
            pages = REDISLIB.get(org_id + '_activity_page')
            if pages is not None:
                for pages in range(int(pages),0,-1):
                    redis_key = org_id + 'activity_' + str(pages) + '_30'
                    REDISLIB.remove(redis_key)
            REDISLIB.remove(org_id + '_activity_1_30')
            REDISLIB.remove(org_id + '_activity_page')
            REDISLIB.remove(org_id + '_activity_count')
            return {STATUS: True, "message": SUCCESS},200
        else:
            return {STATUS: False, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: "org_activity_insert: activity_service_inactive" },400
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: False, ERROR_DES: Errors.error('err_1201') + '[#12702]'}, 401

@bp.route('/fetch/<id>', methods=['GET'])
def fetch_get(id = None) :
    try:   
        if id is None  :
            return {STATUS: False , ERROR_DES: 'invalid_request', RESPONSE: 'Invalid Request'}, 400
        response = activityList(g.org_id, id)
        return response
    except Exception as e:
        return {STATUS: False, ERROR_DES: "fetch_get: " + str(e)}, 401

def activityList(org_id, page) :
    if not page :
        return {STATUS: False , ERROR_DES: 'invalid_request', RESPONSE: 'Invalid Request'}, 400
    
    DEFAULT_PAGE_SIZE = 30
    count = DEFAULT_PAGE_SIZE
    pageOffset = int(page) - 1
    pagestart = int(pageOffset) * count
    start = pagestart// count + 1
    
    ##REDIS CHECK (IF REDIS KEY EXIST) ##
    redis_key = org_id + '_activity_' + str(start) + '_' + str(count)
    rediskey_activity_count = org_id + '_activity_count'
    rediskey_activity_page = org_id + '_activity_page'
   
    redisData = REDISLIB.get(redis_key) 
    if redisData:
        redistotalcount = REDISLIB.get(rediskey_activity_count)
        if type(redisData) == type([]) :
            jsonredisData = redisData
        else:
            jsonredisData = json.loads(redisData)

        response = activitylist_response(jsonredisData, int(redistotalcount))
        return response
    
    ##REDIS CHECK (IF REDIS KEY EXIST)END ##
    ##IF REDIS KEY DOESN'T EXIST##
    collection = "org_activity/"
    where = '?where={"affecteduser":"' + str(org_id) + '"}' # for filtering data
    sort = '&sort=[("timestamp", -1)]'
    count = '&max_results=' + str(count)
    startpage = '&page=' + str(start)
    post_url = org_eve['url']+ collection + where + sort + count + startpage
    post_url = requote_uri(post_url)
    headers = {'connect_timeout' : '40', 'curl_timeout' : '40'}

    curl_result = requests.request(method='GET',url= post_url, headers=headers, auth=HTTPBasicAuth(org_eve['username'], org_eve['password']) )
    resp = curl_result.text
    status_code = curl_result.status_code
    if status_code == 200 :
        responsearray = json.loads(resp)
        if responsearray.get('_meta'):
            
            count_pages = math.ceil(responsearray['_meta'].get('total') / DEFAULT_PAGE_SIZE)
        
            ##SET REDIS KEY##
            REDISLIB.set(redis_key, json.dumps(responsearray.get('_items')))
            REDISLIB.set(rediskey_activity_count, count_pages)
            
            redistotalcount = REDISLIB.get(rediskey_activity_page) if REDISLIB.get(rediskey_activity_page) else 0
            
            if start > int(redistotalcount) :
                REDISLIB.set(rediskey_activity_page, start)
            
            ##SET REDIS KEY END##
            response = activitylist_response(responsearray.get('_items'), count_pages)
            return response
        else:
            return {STATUS: True, 'count' : 0, 'data' : [], MESSAGE : 'activity_service_inactive'}
    else :
        return {STATUS: True, 'count' : 0, 'data' : [], MESSAGE : 'activity_service_inactive'}

def activitylist_response(rowitems, rowcount = '') :
    type1 = {
        "signup","file_created","file_changed","file_esigned","metadata_add","metadata_update","doc_type_update","user_added",
        "user_activated","user_deactivated","assign_role","mobile_updated","email_updated","transfer_ownership","file_locked",
        "file_deleted","file_renamed","uri_saved","uri_deleted","share_self","share_to","move_self","icai_updated","cin_updated",
        "udyam_updated","request_created","request_cancelled","download_shared","esign_consent","create_department",
        "access_department","update_department","department_assign","revoke_department","active_department","create_section","access_section",
        "update_section","assign_section","revoke_section","read","download","user_changed","user_removed"
    }
    activity_response = []
    for row in list(rowitems) :
        data = {}
        data['user'] = row['user']
        data['type'] = row['type']
        data['subject'] = row['subject']
        data['file'] = row['file']
        data['date'] = row['timestamp']
        if data['type'] in type1:
            getfilename =  data['file'] if data['file'] else ""
            # filename = getfilename[-1]
            get_subject = translation(row['app'], data['subject'],data['user'], row['user_affected'], unquote(getfilename),row['role_id'],row['subjectparams'])
            data['message'] = get_subject
        else :
            data['message'] = row['subject']
        activity_response.append(data) 
    return {STATUS: True, 'count':rowcount, 'data': activity_response}


def translation(app, subject,user,user_affected= "", filename="", role_id="",value= ""):
    if not subject:
        return ''
    username = CommonLib.get_profile_details({"digilockerid" :user}).get('username', '')
    username_affected = CommonLib.get_profile_details({"digilockerid" :user_affected}).get('username', '') if user_affected else ""
    prepared_params = filename.replace('\\','')
    if app == 'files':
        switcher = {
            "signup":username + ' registered ' + prepared_params + " with Entity DigiLocker",
            "file_created":username + ' uploaded ' + prepared_params,
            "file_changed":username + ' updated ' + prepared_params,
            "file_esigned":username + ' signed ' + prepared_params,
            "metadata_add": username + ' added File information for ' + prepared_params,
            "metadata_update": username + ' updated file information for ' + prepared_params + ' to ' + (value or ''),
            "doc_type_update": username + ' updated doc type for ' + prepared_params + ' to ' + (value or ''),  
            "user_added": username + ' added ' + username_affected +' with %s access'%(role_id.capitalize() if role_id else '') + ' of' + (value or '') + 'Department',
            "user_changed": username_affected +' with %s access'%(role_id.capitalize() if role_id else '') + ' was added by System',
            "user_activated":username + ' activated ' + username_affected,
            "user_deactivated":username + ' deactivated ' + username_affected,
            "user_removed": username_affected + " was deactivated by System.",
            "assign_role":username + ' assigned ' + (role_id or '') +' access to ' + username_affected,
            "email_updated":username + ' updated email to ' + (value or ''),
            "mobile_updated":username + ' updated mobile to ' + (value or ''),
            "transfer_ownership":username + ' trasferred their ownership to ' + username_affected,
            "file_locked": username + ' locked ' + prepared_params,
            "file_deleted": username + ' deleted ' + prepared_params,
            "file_renamed": username + ' renamed ' + prepared_params + ' to ' + value,
            "saveuri_self_v2": username + ' added ' + prepared_params + ' in Issued Documents',
            "deleteuri_self_v2": username + ' deleted  ' + prepared_params + ' from Issued Documents',
            "share_self": username + ' shared  ' + prepared_params,
            "share_to": value + ' shared  ' + prepared_params + ' in Shared Documents',
            "move_self": username + ' moved  ' + prepared_params,
            "icai_updated":username + ' updated icai to ' + (value or ''),
            "cin_updated":username + ' updated CIN Number to ' + (value or ''),
            "udyam_updated":username + ' updated Udyam Number to ' + (value or ''),
            "request_created":username + ' has requested to add ' + (value or ''),
            "request_cancelled":username + ' cancelled the request for ' + (value or ''),
            "download_shared":(value or '') + ' downloaded ' + (prepared_params or '') + ' shared by ' + username + (' on %s'%role_id if role_id else ''),
            "esign_consent":"Registration Agreement is successfully e-Signed by "+username,
            "create_department": username + ' created '+ (prepared_params or '') + ' Department',
			"access_department": username + ' is now the admin of ' + (prepared_params or '') + ' Department',
			"update_department": username + ' updated '+ (prepared_params or '') + ' Department',
			"department_assign": username + ' added a new ' + (role_id or '') + username_affected + ' to ' + (prepared_params or '') + ' Department',
			"revoke_department": username + ' revoked access for ' + (prepared_params or '') + ' department from ' + username_affected,
            "active_department": username + ' Active access for ' + (prepared_params or '') + ' department from ' + username_affected,
			"create_section": username + ' added '+ (prepared_params or '') + ' Section to ' + (value or '') + ' Department',
			"access_section": username + ' is now the admin of ' + (prepared_params or '') + ' Section in ' + (value or '') + ' Department',
			"update_section": username + ' updated '+ (prepared_params or '') + ' Section in ' + (value or '') + ' Department',
			"assign_section": username + ' added a new ' + (role_id or '') + username_affected + ' to ' + (prepared_params or '') + ' Section of ' + (value or '') + ' Department',
			"revoke_section": username + ' revoked access for ' + (prepared_params or '') + ' Section in ' + (value or '') + ' Department from ' + username_affected,
            "read": username + ' read ' + prepared_params + ' to ' + (role_id or ''),
            "download": username + ' download ' + prepared_params + ' as ' + (role_id or ''),
        }
        return switcher.get(subject,subject)
