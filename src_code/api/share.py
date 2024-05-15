from datetime import datetime
from flask import request, Blueprint, g

from lib.constants import *
from lib.commonlib import CommonLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

Commonlib = CommonLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()

bp = Blueprint('share', __name__)

logs_queue = 'shared_docs_logs_PROD'
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local
SHARED_DOCS_D_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


@bp.before_request
def validate():
    """
        JWT Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.path

        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_login()
            
        if status_code != 200:
            return jwtres, status_code
        g.path = jwtres
        g.jwt_token = jwtlib.jwt_token
        g.did = jwtlib.device_security_id
        g.digilockerid = jwtlib.digilockerid
        
        logarray.update({'digilockerid': g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


# Share API for Bulk Share for DigiLocker to EntityLocker
@bp.route('/entity', methods=['POST'])
def share_v1():
    """
    Share the document from drive/ids to other org.
    """
    try:
        status_code, res = Commonlib.bulkShare_to_Individual(request)
        
        if status_code == 401:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | {"status": "error", "error_description": "MITM attack blocked."}, 'share_v1')
            return res, status_code
        elif status_code != 200:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'share_v1')
            return res, status_code 
        # source = ids for issued documents sharing
        
        uid, shared_by_name, shared_files, valid_till, source, purpose = res

        ''''take path me URI(file_path), shared to, shared_from, source=issued_documents, puprose ->input 
        '''
        valid_till_res = CommonLib.validate_dateformat(valid_till)
        if valid_till_res[0] == 400:
            return valid_till_res[1], valid_till_res[0]
        valid_till = valid_till_res[1]
        
        valid_till_datetime = datetime.strptime(valid_till, "%Y-%m-%d %H:%M:%S")
        current_datetime = datetime.now()

        if valid_till_datetime < current_datetime:
            return {"status": "error", "error_description": "Valid till date cannot be in the past."}, 400
        
        profile = CommonLib.get_profile_details({'digilockerid': g.digilockerid})
        res, status_code = MONGOLIB.org_eve('org_details', {'org_id': g.org_id}, {}, limit=1)
        if status_code != 200 or type(res.get("data")) != type([]) or len(res.get("data")) == 0:
            return {"status": "error", "error_description": "Please enter valid sender's org id."}, 400
        shared_by_email = res["data"][0].get('email')
        
        # Get digilockerid based on uid
        digilockerid = g.digilockerid

        # res = CommonLib.get_profile_details({'digilockerid': digilockerid})
        # shared_to_name = res.get('username')
        # shared_to_email = res.get('email')
        shared_to_name = profile.get('username')
        shared_to_email = profile.get('email')
        
        if not shared_to_email:
            return {"status": "error", "error_description": "Please select digilocker account."}, 400
               
        for data in shared_files:
            sz = 0 #s3_connector.get_size(data['file_path'], collection = data['is_folder']).get('size') or 0
            rowData = {
                'data': {
                    "operation": "share",
                    "shared_to": digilockerid,
                    "shared_by": g.org_id,
                    "shared_by_name": shared_by_name,
                    "shared_to_name": shared_to_name,
                    "shared_to_email": shared_to_email,
                    "shared_by_email": shared_by_email,
                    "shared_by_username": profile['username'],
                    "shared_by_did": g.digilockerid,
                    "file_name": data['file_name'],
                    "file_path": data['file_path'],
                    "is_folder": data['is_folder'],
                    "valid_till": valid_till,
                    "source": source,
                    "purpose": purpose,
                    "size" : sz
                }
            }
            # response = SharedLib().add_to_queue(data=rowData)
            # if response["status"] == "success":
            #     # modifiy activity in case of source ids
            #     send_activity("share_self", "share_self", data['file_path'].split("/")[-1] + ' with ' + shared_to_name)
            #     send_activity("share_to", "share_to", data['file_path'].split("/")[-1], subjectparams=shared_by_name)
            # else:
            #     return {"status": "error", "error_description": "Unable to share all documents. Please try again later."}, 400
            
        return {"status": "success", "message": "Shared"}, 200
    
    except Exception as e:
        return {
            "status": "error",
            "error_description": "Unable to share any documents. Please try again later.",
            "response": f"{str(e)} [#er_018]"
        }, 400


# Bulk Share API for DigiLockerc to DigiLocker. 
@bp.route('/digi', methods=['POST'])
def share_v2():
    """
    Share the document from drive/ids to other org.
    """
    try:
        status_code, res = Commonlib.bulkShareEntity_validation(request)
        if status_code == 401:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | {"status": "error", "error_description": "MITM attack blocked."}, 'share_entity')
            return res, status_code
        elif status_code != 200:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'share_entity')
            return res, status_code 
        # source = ids for issued documents sharing
        
        shared_to, shared_to_name, shared_by_name, shared_files, valid_till, source, purpose = res
        ''''take path me URI(file_path), shared to, shared_from, source=issued_documents, puprose ->input 
        '''
        valid_till_res = CommonLib.validate_dateformat(valid_till)
        if valid_till_res[0] == 400:
            return valid_till_res[1], valid_till_res[0]
        valid_till = valid_till_res[1]

        valid_till_datetime = datetime.strptime(valid_till, "%Y-%m-%d %H:%M:%S")
        current_datetime = datetime.now()
 
        if valid_till_datetime < current_datetime:
            return {"status": "error", "error_description": "Valid till date cannot be in the past."}, 400
        
        profile = CommonLib.get_profile_details({'digilockerid': g.digilockerid})
        receiver_profile = CommonLib.get_profile_details({'digilockerid': shared_to})
        
        try:            
            for data in shared_files:
                sz = 0 #s3_connector.get_size(data['file_path'], collection = data['is_folder']).get('size') or 0
                rowData = {
                     'data': {
                        "operation": "share",
                        "shared_to": shared_to,
                        "shared_by": g.digilockerid,
                        "shared_to_name": shared_to_name,
                        "shared_by_name": shared_by_name,
                        "shared_to_email": profile['email'],
                        "shared_by_email": receiver_profile['email'],
                        "shared_by_username": profile['username'],
                        "shared_by_did": g.digilockerid,
                        "file_name": data['file_name'],
                        "file_path": data['file_path'],
                        "is_folder": data['is_folder'],
                        "valid_till": valid_till,
                        "source": source,
                        "purpose": purpose,
                        "size" : sz
                    }
                }
                # response = SharedLib().add_to_queue(data=rowData)
                # if response["status"] == "success":
                #     # modifiy activity in case of source ids
                #     send_activity("share_self", "share_self", data['file_path'].split("/")[-1] + ' with ' + shared_to_name)
                #     send_activity("share_to", "share_to", data['file_path'].split("/")[-1], subjectparams=shared_by_name)
                # else:
                #     return {"status": "error", "error_description": "Unable to share all the documents. Please try again later."}, 400
            
            return {"status": "success", "message": "Shared"}, 200
        
        except Exception as e:
            return {"status": "error", "error_description": "Unable to share any documents. Please try again later."}, 400
        
    except Exception as e:
        return {"status": "error", "error_description": "Some technical error occured","response": f"{str(e)} [#er_018]"}, 400
    

@bp.route('/by_me', methods = ['POST'])
def by_me():
    logarray = {}
    logarray['digilockerid'] = g.digilockerid
    try:
        where = {"shared_by": g.digilockerid}
        resp, code = MONGOLIB.accounts_eve_v2('shared_docs', where, {}, limit=10000)
        logarray['where'] = json.dumps(where)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_by_me')
        if code == 200:
            if len(resp['response']) > 0:
                data = []
                for d in resp['response']:
                    if d.get('shared_to_name') not in [e['Name'] for e in data]:
                        data.append({
                            "Name": d.get('shared_to_name'),
                            "shared_to": d.get('shared_to'),
                            "shared_on": d.get('shared_on'),
                            'type': "entity" if "entity_individual" in d.get('shared_with','individual') else "individual"
                        })
                return {'status': "success", 'data': data}, code
            return resp, code
        else:
            resp.pop('response', None)
            return resp, 400
            
    except Exception as e:
        resp = {"status": "error","error_description" :str(e)+' [#er_014]'}
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_by_me')
        resp['error_description'] = Errors.error('ERR_MSG_111')
        return resp, 400
    
    
@bp.route('/to_me', methods = ['POST'])
def to_me():
    logarray = {}
    logarray['digilockerid'] = g.digilockerid
    try:
        where = {"shared_to": g.digilockerid}
        resp, code = MONGOLIB.accounts_eve_v2('shared_docs', where, {}, limit=10000)
        logarray['where'] = json.dumps(where)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_to_me')
        if code == 200:
            if len(resp['response']) > 0:
                data = []
                for d in resp['response']:
                    if d.get('shared_by_name') not in [e['Name'] for e in data]:
                        data.append({
                            "Name": d.get('shared_by_name'),
                            "shared_by": d.get('shared_by'),
                            "shared_on": d.get('shared_on'),
                            'type': "entity" if "entity_individual" in d.get('shared_with','individual') else "individual"
                        })
                return {'status': "success", 'data': data}, code
            return resp, code
        else:
            resp.pop('response', None)
            return resp, 400
            
    except Exception as e:
        resp = {"status": "error","error_description" :str(e)+' [#er_017]'}
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_to_me')
        resp['error_description'] = Errors.error('ERR_MSG_111')
        return resp, 400


@bp.route('/by_me_list', methods = ['POST'])
def by_me_list():
    logarray = {}
    logarray['digilockerid'] = g.digilockerid
    try:
        status_code, res = Commonlib.shared_by_me_list_val(request)
        if status_code == 400:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'shared_by_me_list')
            return res, status_code
        else:
            shared_to, path = res
        
        where = {"shared_by": g.digilockerid, "shared_to": shared_to}
        resp, code = MONGOLIB.accounts_eve_v2('shared_docs', where, {}, limit=10000)
        logarray['where'] = json.dumps(where)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_by_me_list')
        if code != 200:
            resp.pop('response', None)
            return resp, code
        data = []
        if len(resp['response']) > 0:
            for d in resp['response']:
                file_data = {
                    "shared_id": d.get("shared_id"),
                    "Name": d.get('path', '').split("/")[-1] if d.get("source") != "ids" else d.get('file_name', ""),
                    "Ext": "Collection" if d.get('is_folder') == "Y" else d.get('path', '').split("/")[-1].split(".")[-1],
                    "Key": d.get('path'),
                    "LastModified": d.get('shared_on'),
                    "ValidTill": d.get("valid_till"),
                    "source": d.get("source"),
                    "purpose": d.get("purpose"),
                    "size": d.get('size'),
                    "shared_with": d.get('shared_with','individual')
                }
                if not d.get("revoked_on") and datetime.strptime(d.get('valid_till'), SHARED_DOCS_D_FORMAT) > datetime.now():
                    file_data['status'] = "active"
                elif d.get("revoked_on"):
                    file_data['status'] = "revoked"
                else:
                    file_data['status'] = "inactive"
                data.append(file_data)
        return {'status': "success", 'data': data}, code
    except Exception as e:
        resp = {"status": "error","error_description" :str(e)+' [#er_015]'}
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_by_me_list')
        resp['error_description'] = Errors.error('ERR_MSG_111')
        return resp, 400    


# shared with me
@bp.route('/to_me_list', methods = ['POST'])
def to_me_list():
    logarray = {}
    logarray['digilockerid'] = g.digilockerid
    try:
        status_code, res = Commonlib.shared_to_me_list_val(request)
        if status_code == 400:
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'shared_to_me_list')
            return res, status_code
        else:
            shared_by, path = res
        where = {"shared_to": g.digilockerid, "shared_by": shared_by}
        resp, code = MONGOLIB.accounts_eve_v2('shared_docs', where, {}, limit=10000)
        logarray['where'] = json.dumps(where)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_to_me_list')
        if code == 200:
            if len(resp['response']) > 0:
                data = []
                for d in resp['response']:
                    file_data = {
                        "shared_id": d.get("shared_id"),
                        "Name": d.get('path', '').split("/")[-1] if d.get("source") != "ids" else d.get('file_name', ""),
                        "Ext": "Collection" if d.get('is_folder') == "Y" else d.get('path', '').split("/")[-1].split(".")[-1],
                        "Key": d.get('path'),
                        "LastModified": d.get('shared_on'),
                        "ValidTill": d.get("valid_till"),
                        "source": d.get("source"),
                        "purpose": d.get("purpose"),
                        "size": d.get('size'),
                        "shared_with": d.get('shared_with','individual')
                    }
                    if not d.get("revoked_on") and datetime.strptime(d.get('valid_till'), SHARED_DOCS_D_FORMAT) > datetime.now():
                        file_data['status'] = "active"
                    elif d.get("revoked_on"):
                        file_data['status'] = "revoked"
                    else:
                        file_data['status'] = "inactive"
                    data.append(file_data)
                return {'status': "success", 'data': data}, code
            return resp, code
        else:
            resp.pop('response', None)
            return resp, 400
    except Exception as e:
        resp = {"status": "error","error_description" :str(e)+' [#er_016]'}
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | resp, 'shared_to_me_list')
        resp['error_description'] = Errors.error('ERR_MSG_111')
        return resp, 400


@bp.route('/list_folder', methods = ['POST'])
def list_folder():
    logarray = {}
    try:
        res, code = Commonlib.list_folder(request)
        if code != 200:
            logarray['status_code'] = code
            logarray['body'] = dict(request.values)
            logarray['headers'] = dict(request.headers)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'list_folder')
            return res, code
        shared_id, shared_with, path = res
        if shared_with == "entity_individual":
            profile = CommonLib.get_profile_details({'digilockerid': g.digilockerid})
            headers = {'orgid': g.digilockerid, 'orgname': profile['username']}
            res, code = Commonlib.org_drive_api('list_shared', headers=headers, data={"shared_id": shared_id, "path": path})
            if code != 200:
                logarray['status_code'] = code
                logarray['body'] = dict(request.values)
                logarray['headers'] = dict(request.headers)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'list_folder')
        else:
            res, code = {'status': 'error', 'error_description': "This feature is only currently available to access documents shared from entity to digilocker account."}, 400
        logarray['status'] = 'success'
        logarray['status_code'] = 200
        logarray['path'] = 200
        logarray['content_length'] = len(res)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, 'list_folder')
        return res, code
    except Exception as e:
        ## logstash for exception for list function 
        res = {"status": "error","error_description" :str(e)+' [#er_002]'}
        code = 400
        logarray['status_code'] = code
        logarray['body'] = dict(request.values)
        logarray['headers'] = dict(request.headers)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'list_folder')
        return res, code


@bp.route('/read', methods = ['POST'])
def read():
    logarray = {}
    try:
        res, code = Commonlib.read(request)
        if code != 200:
            logarray['status_code'] = code
            logarray['body'] = dict(request.values)
            logarray['headers'] = dict(request.headers)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'read')
            return res, code
        shared_id, shared_with, path = res
        if shared_with == "entity_individual":
            profile = CommonLib.get_profile_details({'digilockerid': g.digilockerid})
            res, code = Commonlib.org_drive_api(
                'read_shared',
                headers = {'orgid': g.digilockerid, 'orgname': profile['username']},
                data = {"shared_id": shared_id, "path": path}
            )
            if code != 200:
                logarray['status_code'] = code
                logarray['body'] = dict(request.values)
                logarray['headers'] = dict(request.headers)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'read')
        else:
            res, code = {'status': 'error', 'error_description': "This feature is only currently available to access documents shared from entity to digilocker account."}, 400
        logarray['status'] = res.get('status', 'error')
        logarray['status_code'] = code
        logarray['path'] = read
        logarray['content_length'] = len(json.dumps(res))
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, 'read')
        return res, code
    except Exception as e:
        ## logstash for exception for list function 
        res = {"status": "error","error_description" :str(e)+' [#er_002]'}
        code = 400
        logarray['status_code'] = code
        logarray['body'] = dict(request.values)
        logarray['headers'] = dict(request.headers)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'read')
        return res, code
    
    
@bp.route('/download', methods = ['POST'])
def download():
    logarray = {}
    try:
        res, code = Commonlib.download(request)
        if code != 200:
            logarray['status_code'] = code
            logarray['body'] = dict(request.values)
            logarray['headers'] = dict(request.headers)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'download')
            return res, code
        res, code = Commonlib.org_drive_api('read_shared'+res, "GET")
        if code != 200:
            logarray['status_code'] = code
            logarray['body'] = dict(request.values)
            logarray['headers'] = dict(request.headers)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'download')
        logarray['status'] = 'success'
        logarray['status_code'] = 200
        logarray['path'] = 200
        logarray['content_length'] = len(res)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray, 'download')
        return res, code
    except Exception as e:
        ## logstash for exception for list function 
        res = {"status": "error","error_description" :str(e)+' [#er_002]'}
        code = 400
        logarray['status_code'] = code
        logarray['body'] = dict(request.values)
        logarray['headers'] = dict(request.headers)
        RABBITMQ_LOGSTASH.log_stash_logeer(logarray | res, 'download')
        return res,code