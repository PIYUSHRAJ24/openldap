import hashlib
import datetime
import time
from base64 import b64decode, b64encode, encodebytes
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import request, Blueprint, g

from lib.connectors3 import Connectors3
from lib.constants import *
from lib.drivejwt import DriveJwt
# from lib.elasticlib import ElasticLib
# from lib.extractor import Extractor
from lib.mongolib import MongoLib
from api.org_activity  import activity_insert
from lib.rabbitmq import RabbitMQ
# from lib.tokenizer import Tokenizer
from lib.validations import Validations
from lib.secretsmanager import SecretManager
import re

from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
# from api.org import esign_consent_get
rmq = RabbitMQTaskClientLogstash()

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

# EXTRACTOR = Extractor()
# TOKENIZER = Tokenizer()
VALIDATIONS = Validations()
ELASTICLIB = ElasticLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
CONNECTORS3 = Connectors3()

bp = Blueprint('metadata', __name__)

rmq_queue = 'org_drive_logs'

@bp.before_request
def validate():
    """
        JWT Authentication
    """
    request_data = request.values
    g.logs = {'post_data': dict(request_data), 'req_header': {**request.headers}}
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.path
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_login_org()
        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
            g.digilockerid = jwtlib.digilockerid
            g.role = jwtlib.user_role
            g.org_id = jwtlib.org_id
            if not g.org_id and not VALIDATIONS.is_valid_did(g.org_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_123')}, 401
            if not g.digilockerid and not VALIDATIONS.is_valid_did(g.digilockerid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 401
            # consent_status, consent_code = esign_consent_get()
            # if consent_code != 200 or consent_status.get(STATUS) != SUCCESS or not consent_status.get('consent_time'):
            #     return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        else:
            return jwtres, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#401)"+str(e), "step":"before_req"}
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'metadata')
        res.pop('step')
        return res, 401


def check_alphanumeric(string):
    alphanumeric = re.sub(r'\W+', '', string)
    if len(alphanumeric) > 50:
        return {"status":"error", "message":"Metadata must contain 50 or fewer alphanumeric characters."}, 400

'''This API used on click of edit button for uploaded Files'''

@bp.route('/update', methods=['POST'])
def update():
    
    if g.role != 'ORGR001':
        res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
        res['step'] = 'update'
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'metadata')
        return res, 417
    
    # Parse input data
    file_name_input = request.values.get("name")  
    if file_name_input == None or len(file_name_input.split('.')) == 1:
        res = {"status": "error","error_description" :"Invalid file name provided."}
        code = 400
        return res, code
    
    path = g.path
    if file_name_input:
        file_path = path + file_name_input
    
    doc_type = request.values.get("doc_type")
    metadata = request.values.get("meta_data")

    # Validate input data
    check_alphanumeric(metadata)
    if not file_path:
        return {"status": "error", "message": "File path is required"}, 400
    # Extract file name and path
    file_name = file_path.split('/')[-1] + '.json'
    path = '/'.join(file_path.split('/')[:-1]) + '/'
    # Retrieve and update JSON file
    try:
        resp = get_file(path, file_name)
        if resp['status'] == "success":
            contents = resp['Body']
            decoded = json.loads(contents)
            if doc_type:
                decoded.update({'doc_type': doc_type, "doc_modified_on": time.time()})
                act_resp = activity_insert("doc_type_update","doc_type_update",g.digilockerid,g.org_id,doc_name = file_path.split('/')[-1],subjectparams=doc_type) 
                rmq.log_stash_logeer({"Activity_update": "updatemeta-doc_type", RESPONSE: act_resp}, rmq_queue, 'metadata')
            
            if metadata:
                unique_metadata = decoded['metadata']  # remove duplicates
                if metadata in unique_metadata:
                    unique_metadata.remove(metadata)
                if metadata not in unique_metadata:
                    unique_metadata.append(metadata)
                    decoded.update({"tag_modified_on": time.time(), 'metadata':unique_metadata})
                    
                CONNECTORS3.file_upload_obj(path, file_name, json.dumps(decoded))
                act_resp = activity_insert("metadata_update","metadata_update",g.digilockerid,g.org_id,doc_name = file_path.split('/')[-1],subjectparams=metadata) 
                rmq.log_stash_logeer({"Activity_update": "updatemeta", RESPONSE: act_resp}, rmq_queue, 'metadata')
                res = {"status": "success", "message": "File updated"}
                code = 200
            else:
                res = {"status": "error", "message": "invalid input(#T-422)"}
                code = 400
        else:
            res = {"status": "error", "message": "Technical Issue (#T-400)"}
            code = 400
        
        res['step'] = 'update'
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'metadata')
        res.pop('step')
        return res, code
    except Exception as e:
        return {"status": "error", "message": "Technical Issue (#T-400)"}, 400


def get_file(path, file_name, ops=None):
    try:
        Body,ContentType = CONNECTORS3.read_obj(path,file_name,ops)
        if ContentType == 400:
            return Body
        else:
            return {"status": "success","ContentType":ContentType,"Body":Body}
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Unable to locate file.(#400)"}
