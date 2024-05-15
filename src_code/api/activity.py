from flask import request, Blueprint, g
from lib.drivejwt import DriveJwt
from lib.redislib import RedisLib
from lib.commonlib import CommonLib
from lib.rabbitmq import RabbitMQ
from lib.validations import Validations
from lib.constants import *
import time, json, requests, math
from urllib.parse import unquote
from requests.utils import requote_uri
from requests.auth import HTTPBasicAuth
from lib.secretsmanager import SecretManager

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

VALIDATIONS = Validations()
COMMONLIB = CommonLib()
REDISLIB = RedisLib()
RABITMQ = RabbitMQ()

bp = Blueprint('activity', __name__)


@bp.before_request
def validate_user():
    """
        Jwt Authentication
    """
    try:
        g.hmac = request.values.get('hmac',None)
        if g.hmac is None:
            if request.method == 'OPTIONS':
                return {"status": "error", "error_description": "OPTIONS OK"}
            bypass_urls = ('healthcheck')
            if request.path.split('/')[1] in bypass_urls:
                return

            jwtlib = DriveJwt(request, CONFIG)

            jwtres, status_code = jwtlib.jwt_login()

            if status_code == 200:
                g.path = jwtres
                g.jwt_token = jwtlib.jwt_token
                g.did = jwtlib.device_security_id
            else:
                return jwtres, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route('/healthcheck', methods=['POST'])
def healthcheck():
    return True

@bp.route('/activity_insert', methods=['POST'])
def activity_insert():
    try:
        res, status_code = COMMONLIB.validation_rules(request)
        print(res)
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            return res, status_code

        res, status_code = VALIDATIONS.activity_insert(request)
        if status_code == 400:
            return res, status_code
        type = res['type']
        subject = res['subject']
        doc_name = res['doc_name']   

        affecteduser = user
        priority = 40
        app = "files"
        subjectparams = ""
        message = ""
        messageparams = "a:0:{M}"
        link = ""
        
        post_data = {
            "activity_id" : int(time.time()),
            "user" : user,
            "affecteduser" : affecteduser,
            "timestamp" : int(time.time()),
            "type" : type,
            "priority" : priority,
            "app" : app,
            "subject" : subject,
            "subjectparams" : subjectparams,
            "message" : message,
            "messageparams" : messageparams,
            "file" : doc_name,
            "link" : link,
        }
        
        mq_status,status_code = RABITMQ.send_to_queue(post_data, 'Mongo_Xchange','Activity_')
        mq_status['step'] = 'activity_insert'
        
        if status_code==200:
            pages = REDISLIB.get(user + '_activity_page')
        
            for pages in range(int(pages),0,-1):
                redisKey = user + 'activity_' + str(pages) + '_30'
                REDISLIB.remove(redisKey)
            REDISLIB.remove(user + '_activity_1_30')
            REDISLIB.remove(user + '_activity_page')
            REDISLIB.remove(user + '_activity_count')
            return {STATUS: SUCCESS},200
        else:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: "activity_insert: activity_service_inactive" + "str(e)"},400
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "activity_insert: " + str(e)}, 401


@bp.route('/fetch_get/<id>', methods=['GET'])
def fetch_get(id = None) :
    try:   
        if id is None  :
            return {STATUS: ERROR , ERROR_DES: 'invalid_request', RESPONSE: 'Invalid Request'}, 400
        
        username = g.path.split('/')[0]
        
        response = activityList(username, id)
        return response
        
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "fetch_get: " + str(e)}, 401

def activityList(user, page) :
    
    if not page :
        return {STATUS: ERROR , ERROR_DES: 'invalid_request', RESPONSE: 'Invalid Request'}, 400
    
    DEFAULT_PAGE_SIZE = 30

    pageOffset = int(page) - 1
    pagestart = int(pageOffset) * int(DEFAULT_PAGE_SIZE)
    count = DEFAULT_PAGE_SIZE
    apps = 'shared,file_created,file_changed,file_deleted,file_esigned,oauth_unlink,oauth_link,oauth_access,uri_deleted,pin_changed,uri_saved,uri_pushed,bank_login,bank_user_deactive,file_restored,remote_share,public_links'
    
    affecteduser = '"affecteduser":"' + user + '"'
    app = '"type": : "in": ["' + apps.replace(',', '","') + '"]'
    #where = '?where=:' + affecteduser + ',' + app + '' # for filtering data
    where = '?where={' + affecteduser+ '}' # for filtering data
    
    sort = '&sort=[("timestamp", -1)]'
    start = int(int(pagestart) / int(count) + 1)
    
    ##REDIS CHECK (IF REDIS KEY EXIST) ##
    redisKey = user + '_activity_' + str(start) + '_' + str(count)
    redis_tot_activity = user + '_activity_count'
    redis_activity_page = user + '_activity_page'
   
    redisData =  REDISLIB.get(redisKey) #test this part
    
    if redisData:
        redistotal = REDISLIB.get(redis_tot_activity)
        if type(redisData) == type([]) :
            jsonredisData = redisData
        else:
            jsonredisData = json.loads(redisData)

        response = activitylist_response(jsonredisData, int(redistotal))
        return response
    ##REDIS CHECK (IF REDIS KEY EXIST)END ##
    ##IF REDIS KEY DOESN'T EXIST##
    startpage = '&page=' + str(start)
    count = '&max_results=' + str(count)
    post_url = os.getenv('activityApiUrl') + where + sort + count + startpage
    post_url = requote_uri(post_url)
    
    headers = {'connect_timeout' : '40', 'curl_timeout' : '40'}
    auth = os.getenv('activity_api_pass').split(':')
    username = auth[0]
    password = auth[1]
    
    curl_result = requests.request(method='GET',url= post_url, headers=headers, auth=HTTPBasicAuth(username, password) )
    output = curl_result.text
    status_code = curl_result.status_code
    
    if status_code == 200 :
        responsearray = json.loads(output)
        count_pages = math.ceil(responsearray['_meta']['total'] / DEFAULT_PAGE_SIZE)
        
        ##SET REDIS KEY##
        REDISLIB.set(redisKey, json.dumps(responsearray['_items']))
        REDISLIB.set(redis_tot_activity, count_pages)
        
        redistotal = REDISLIB.get(redis_activity_page)if REDISLIB.get(redis_activity_page) else 0
        
        if start > int(redistotal) :
            REDISLIB.set(redis_activity_page, start)
        
        ##SET REDIS KEY END##
        response = activitylist_response(responsearray['_items'], count_pages)
        return response
    else :
        return {STATUS:SUCCESS, 'count' : 0, 'data' : [], MESSAGE : 'activity_service_inactive'}

def activitylist_response(rowitems, rowcount = '') :
    type1 = {'shared', 'file_created', 'file_changed', 'pin_changed', 'uri_deleted', 'file_deleted', 'file_esigned', 'oauth_unlink', 'oauth_link', 'oauth_access', 'uri_saved', 'uri_pushed', 'bank_login', 'bank_user_deactive', 'file_restored', 'remote_share', 'public_links', 'profile_update', 'nominee_update', 'shared_profile'}
    
    user_activity = []
    data = {}
    for row in list(rowitems) :
        data['user'] = row['user']
        data['type'] = row['type']
        data['subject'] = row['subject']
        data['file'] = row['file']
        data['date'] = row['timestamp']

        if data['type'] in  type1:
            getfilename =  data['file'].split('/')
            filename = getfilename[len(getfilename) - 1]

            get_subject = translation(row['app'], data['subject'], unquote(filename))  
            data['message'] = get_subject
        else :
            data['message'] = row['subject']
        
        user_activity.append(data) 
    return {STATUS:SUCCESS, 'count':rowcount, 'data': user_activity}


def translation(app, text, params):
    if not text:
        return ''
    
    preparedParams = params.replace('\\','')
    if app == 'files':
        switcher = {
            "created_self":'You uploaded ' + preparedParams,
            "created_by":'You created ' + preparedParams,
            "created_public":preparedParams + ' was created in a public folder',
            "changed_self": 'You changed ' + preparedParams,
            "changed_by": 'You changed ' + preparedParams,
            "deleted_self": 'You deleted ' + preparedParams,
            "deleted_by":'You deleted ' + preparedParams,
            "renamed_self":'You renamed ' + preparedParams,
            "restored_self":'You restored ' + preparedParams,
            "reset_pin":'You changed security PIN',
            "m_pin": 'You changed MPIN ',
            "deleteuri_self":'You deleted ' + preparedParams + ' from your Issued Documents section',
            "urideleted_self":'You deleted ' + preparedParams + ' from your Issued Documents section',
            "urideleted_by": 'You deleted ' + preparedParams + ' from your Issued Documents section',
            "saveuri_self": 'You pulled your ' + preparedParams + ' database and saved the link to your Issued Documents section',
            "saveuri_self_v2": 'You added ' + preparedParams + ' in Issued Documents',
            "shared_link_self": 'You shared ' + preparedParams + 'via link',
            "esigned_self": 'You eSigned ' + preparedParams,
            "deleteuri_self": 'You deleted ' + preparedParams + ' from your Issued Documents',
            "deleteuri_self_v2": 'You deleted ' + preparedParams + ' from your Issued Documents',
            "banklogin_self": 'You' + preparedParams,
            "bankuserdeactive_self": preparedParams,
            "oauthunlink_self": 'You removed access from ' + preparedParams,
            "oauthunlink_by":'You removed the authorization of ' + preparedParams + ' to access your DigiLocker',
            "oauthlink_self": 'You authorized access to ' + preparedParams,
            "oauthlink_by": preparedParams + ' documents',
            "oauthaccess_by": preparedParams,
            "profile_created_self": 'You have generated your profile of documents list(s) ' + preparedParams,
            "profile_shared_self":'You have shared your profile of ' + preparedParams,
            "uri_pushed_by_v2":preparedParams + ' to your Issued Documents' ,#<Issuer-name> has added <Doc Name>
        }    
        return switcher.get(text,text)