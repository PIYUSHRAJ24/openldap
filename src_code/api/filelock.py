from flask import request, Blueprint, g
from lib.constants import *
from lib.validations import Validations
# from lib.elasticlib import ElasticLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.connectors3 import Connectors3
from base64 import b64decode
import hashlib
from lib.secretsmanager import SecretManager
from base64 import b64encode
from api.org_activity  import activity_insert
from lib.redislib import RedisLib
rs = RedisLib()
import datetime
CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

VALIDATIONS = Validations()
# ELASTICLIB = ElasticLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
CONNECTORS3 =Connectors3()

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
rmq = RabbitMQTaskClientLogstash()
rmq_queue = 'org_drive_logs'

bp = Blueprint('filelock', __name__)

@bp.before_request
def validate():
    """
        JWT Authentication
    """
    request_data = {
            'time_start': datetime.datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
    request.logger_data = request_data
    
    request_data = request.values
    g.logs = {'post_data': dict(request_data), 'req_header': {**request.headers}}
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_login()
        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
            g.org_id = jwtlib.org_id
            g.digilockerid = jwtlib.digilockerid
        else:
            return jwtres, status_code
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#401)", "step":"before_req"}
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, 401

def encrypt(text=None, password=None):
    locked = "LOCKED"
    private_key = bytes(hashlib.md5(password.encode()).hexdigest(), 'utf-8')
    iv= Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(text.encode("UTF-8"), AES.block_size))
    return locked + b64encode(iv + encrypted).decode('utf-8').replace('+', '---')

@bp.route('/decrypt', methods=['POST'])
def decrypt():
    file_path = request.values.get("file_path")
    secret = g.org_id[:16]
    status, code = VALIDATIONS.file_lock(request, secret)
    if code == 400:
        return status, code
    elif code == 200:
        user_password = status
    user_password = request.values.get("user_password")
    splited_path = file_path.split('/')
    file_name = splited_path.pop(-1)
    path = '/'.join(splited_path)+'/'
    try:
        resp = get_file(path, file_name)
        if resp['status'] == "success" and resp['Body'][:6] == bytes('LOCKED', 'utf-8'):
            b64_check = resp['Body']
            b64 = b64_check[6:]
            enc = b64.decode('utf-8').replace('---', '+')
            private_key = bytes(hashlib.md5(user_password.encode()).hexdigest(), 'utf-8')
            enc = b64decode(enc)
            iv = enc[:16]
            cipher = AES.new(private_key, AES.MODE_CBC, iv)
            dff  = unpad(cipher.decrypt(enc[16:]), AES.block_size)
            df = dff.decode('utf-8')
            res = {"status":"success","status_code":200,"ContentType":"binary/octet-stream","Body":df}
            code = 200
        else:
            res = {STATUS: ERROR, ERROR_DES: "Invalid Password.(#P-400)"}
            code = 400
        
        res['step'] = 'decrypt'
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, code
        
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#D-400)"}
        code = 400
        res['step'] = 'exception_decrypt'
        g.logs['actual_error'] = str(e)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, code

@bp.route('/file_lock', methods=['POST'])
def file_lock():
    try:
        temp_folder = CONFIG['encrypt']['TMPPATH']
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#T-404)"+str(e)}
        res['step'] = 'file_lock_excp_1'
        g.logs['actual_error'] = str(e)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, 404
    try:
        secret = g.org_id[:16]
        status, code = VALIDATIONS.file_lock(request, secret)
        
        if code == 400:
            return status, code
        elif code == 200:
            user_password = status.strip()
        file_path = request.values.get("file_path")
        splited_path = file_path.split('/')
        file_name = splited_path.pop(-1)
        path = '/'.join(splited_path)+'/'
        file_name_hash = hashlib.md5(path.encode()).hexdigest() +'.'+ file_name.split('.')[-1]
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technial Issue.(#C-422)"}
        res['step'] = 'file_lock_excp_2'
        g.logs['actual_error'] = str(e)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, 422
    
    resp = get_file(path, file_name, 'enc')
    if resp['status'] == "success":
        b64_check =  resp['Body']
        b64 = b64_check
    else:
        return resp
    ##########CHEK FOR LOCK Flag in filedata############
    try:
        if b64_check[:8] == "TE9DS0VE":
            g.logs['step'] = 'file_already_locked'
            rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
            return {STATUS: ERROR, ERROR_DES: "File Already Locked.(#L-422)"}, 422
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#L-400)"}
        res['step'] = 'file_lock_excp_3'
        g.logs['actual_error'] = str(e)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, 400

    try:
        b64 = encrypt(b64, user_password)
        act_resp = activity_insert("file_locked","file_locked",g.digilockerid,g.org_id,doc_name = file_name) 
        rmq.log_stash_logeer({"Activity_update": "file_lock", RESPONSE: act_resp}, rmq_queue, 'filelock')
        path_from_local = temp_folder + file_name_hash
        
        res, code = file_upload(path_from_local, path,file_name, b64)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        return res, code

    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "Technical Issue.(#U-400)"}
        res['step'] = 'file_lock_excp_4'
        g.logs['actual_error'] = str(e)
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue, 'filelock')
        res.pop('step')
        return res, 400

def updatemeta(path, file_name, metadata):
    try:
        resp = get_file(path, file_name+'.json')
        if resp['status'] == "success":
            contents = resp['Body']
            decoded = json.loads(contents)
            decoded.update(metadata)
        CONNECTORS3.file_upload_obj(path, file_name+'.json', json.dumps(decoded))
        act_resp = activity_insert("metadata_update","metadata_update",g.digilockerid,g.org_id,doc_name = file_name+'.json') 
        rmq.log_stash_logeer({"Activity_update": "updatemeta", RESPONSE: act_resp}, rmq_queue, 'updatemeta')
        return {"status": "success","Description":'updated'}
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Unable to locate file.(#M-404)"}, 400

def get_file(path, file_name, ops=None):
    try:
        Body,ContentType = CONNECTORS3.read_obj(path,file_name,ops)
        if ContentType == 400:
            return Body
        else:
            return {"status": "success","ContentType":ContentType,"Body":Body}
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Unable to locate file.(#400)"}, 400

def file_upload(path_from_local, path_to_s3, file_name_upload, file):
    try:
        upload_res, status_code = CONNECTORS3.file_upload_obj(path_to_s3, file_name_upload, file)
        act_resp = activity_insert("file_created","file_created",g.digilockerid,g.org_id,doc_name = file_name_upload) 
        rmq.log_stash_logeer({"Activity_update": "file_upload", RESPONSE: act_resp}, rmq_queue, 'file_upload')
        #upload metadata file for locked #
        metadata = {"islocked": "yes"}
        updatemeta(path_to_s3, file_name_upload, metadata)
        return upload_res, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Unable to upload file.(#400)", "actual_error":str(e)}, 400
    
@bp.after_request
def after_request(response):
    try:
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
        
        
        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'time_end': datetime.datetime.utcnow().isoformat()
        }
        log_data = {
            'request': request.logger_data,
            'response': response_data
        }
        logger.info(log_data)
        return response
    except Exception as e:
        print(f"Logging error: {str(e)}")
    return response

@bp.errorhandler(Exception)
def handle_exception(e):
    log_data = {
        'error': str(e),
        'time': datetime.datetime.utcnow().isoformat()
    }
    logger.error(log_data)
    response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
    response.status_code = 500
    return response    