from flask import request, Blueprint, g, render_template
from lib.constants import *
from lib.validations import Validations
# from lib.elasticlib import ElasticLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.connectors3 import Connectors3
from api.org_activity  import activity_insert
from lib.secretsmanager import SecretManager
import PyPDF2
from base64 import b64decode
import hashlib
import os
from base64 import b64encode
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
# from api.org import esign_consent_get
rmq = RabbitMQTaskClientLogstash()

VALIDATIONS = Validations()
# ELASTICLIB = ElasticLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
CONNECTORS3 =Connectors3()


CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random


bp = Blueprint('lockpdf', __name__)
logarray = {}

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
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'get_count')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.path
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_login_org()
        g.logs = {'post_data': dict(request.values), 'req_header': {**request.headers}}
        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
            g.digilockerid = jwtlib.digilockerid
            g.org_id = jwtlib.org_id
            g.role = jwtlib.user_role
            
            # consent_status, consent_code = esign_consent_get()
            # if consent_code != 200 or consent_status.get(STATUS) != SUCCESS or not consent_status.get('consent_time'):
            #     return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        else:
            return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "Technical Issue.(#401)"}, 400

def checklock(file_path,file_name):
    resp = get_file(file_path, file_name+'.json')
    if resp['status'] == "success":
        body = json.loads(resp['Body'].decode('utf-8'))
        return body['islocked']
    else:
        return "error"

@bp.route('/lock', methods=['POST'])
def lock():
    try:
        if g.role != 'ORGR001':
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_150')}
            res['step'] = 'update'
            rmq.log_stash_logeer({**res, **g.logs}, "org_drive_logs", 'metadata')
            return res, 417
        
        temp_folder = '/opt/enc_temp/'
        # path is like - be9284f2-2251-4f07-989336d15b3/files/NonDisclosureAgreementforinterns.pdf
        file_name_input = request.values.get("name")  
        if file_name_input == None or len(file_name_input.split('.')) == 1:
            res = {"status": "error","error_description" :"Invalid file name provided."}
            code = 400
            return res, code
        
        path = g.path
        if file_name_input:
            file_path = path + file_name_input
        
        
        secret = g.org_id[:16]
        status, code = VALIDATIONS.file_lock(request, secret)
        if code == 400:
            return status, code
        elif code == 200:
            user_password = status.strip()
        splited_path = file_path.split('/')
        file_name = splited_path.pop(-1)
        if splited_path[0] not in g.org_id:
            res = {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_160')}, 401
            logarray.update({RESPONSE: res})
            rmq.log_stash_logeer(logarray, "org_drive_logs", "filelock")
            return render_template(FORCED_ACCESS_TEMPLATE)
        path = '/'.join(splited_path)+'/'
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Technical Error: (C#404)"}, 404
    if checklock(path, file_name) == 'yes':
        return {STATUS: ERROR, ERROR_DES: "File Already Locked.(#L-422)"}, 422
    try:
        file_name_hash = hashlib.md5(path.encode()).hexdigest() +'.'+ file_name.split('.')[-1]
        resp = get_file(path, file_name)
        if resp['status'] == "success":
            b64 = resp['Body']
            b64 = b64encode(b64).decode("UTF-8")
        else:
            return resp
        path_from_local = temp_folder + file_name_hash
        bytes = b64decode(b64, validate=True)
        f = open(path_from_local, 'wb')
        f.write(bytes)
        f.close()
        res = file_lock_core(temp_folder, file_name_hash,user_password)
        response = file_upload(path_from_local, path, file_name)
        return response
        if response['status'] == "success":
            if os.path.exists(path_from_local):
                os.remove(path_from_local)
        return {STATUS:SUCCESS,"response":res}
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "lock exception(#L-400)"}, 400


def file_lock_core(temp_folder, file_name_hash, user_password):
    tmp_path = temp_folder + file_name_hash
    pdf_in_file = open(tmp_path,'rb')
    try:
        inputpdf = PyPDF2.PdfReader(pdf_in_file)
        pages_no = len(inputpdf.pages)
        output = PyPDF2.PdfWriter()
        for i in range(pages_no):
            inputpdf = PyPDF2.PdfReader(pdf_in_file)
            output.add_page(inputpdf.pages[i])
            output.encrypt(user_password)
            #with open("simple_password_protected.pdf", "wb") as outputStream:
            with open(tmp_path, "wb") as outputStream:
                output.write(outputStream)
        pdf_in_file.close()
        return {STATUS:SUCCESS}
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "lock exception: " + str(e)}, 400

def updatemeta(path, file_name, metadata):
    try:
        resp = get_file(path, file_name+'.json')
        if resp['status'] == "success":
            contents = resp['Body']
            decoded = json.loads(contents)
            decoded.update(metadata)
        else:
            decoded = metadata
        CONNECTORS3.file_upload_obj(path, file_name+'.json', json.dumps(decoded))
        return {"status": "success","Description":'updated'}
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "Unable to locate file.(#M-404)"}, 400

def get_file(path, file_name):
    try:
        Body,ContentType = CONNECTORS3.read_obj(path,file_name)
        if ContentType == 400:
            return Body
        else:
            return {"status": "success","ContentType":ContentType,"Body":Body}
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "get_image: " + str(e)}, 400

def file_upload(path_from_local, path_to_s3, file_name_upload):
    try:
        file = open(path_from_local,"rb")
        upload_res,status_code = CONNECTORS3.file_upload_obj(path_to_s3, file_name_upload, file)
        act_resp = activity_insert("file_locked","file_locked",g.digilockerid,g.org_id,doc_name = file_name_upload)
        logarray.update({"Activity_update": "filelock file upload", "response": act_resp})
        #upload metadata file for locked #
        metadata = {"islocked": "yes"}
        updatemeta(path_to_s3, file_name_upload, metadata)
        rmq.log_stash_logeer(logarray, 'org_drive_logs', 'filelock')
        return upload_res,status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "Unable to upload file.(#400)", "actual_error":str(e)}, 400
