import os
import jwt
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv
from flask import Blueprint, request, g
from lib.constants import *
from lib.validations import Validations
from lib.mongolib import MongoLib
from lib.secretsmanager import SecretManager
from lib.cryptographer import Crypt
from lib.commonlib import CommonLib
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
from lib.utils import load_credential, load_apk_signature
from api.authlib import verify_pin, get_users, aes_decryption

load_credential()
load_apk_signature()

rmq = RabbitMQTaskClientLogstash()
rmq_queue = 'ACS_api_logs_verify_pin'

MONGOLIB = MongoLib()
VALIDATIONS = Validations()

bp = Blueprint('validate_pin', __name__)

secrets = CONFIG['DEVICE_CRED'].get('JWT_SECRET')
secret = bytes(secrets, 'utf-8')
apk_sign_key_hash= CONFIG["apk_sigin_key_hash"]

@bp.after_request
def add_header(response) :
    ''' add header'''
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Permissions-Policy"] = "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()"
    response.headers['K-TYPE'] = g.ktype    
    if g.ktype== 'r' or g.ktype== 'd' or g.ktype== 'er' or g.ktype== 'ed' :
        response.headers['X-VALUE'] = g.xval 
    else :
        response.headers['X-VALUE'] = '' 
    return response

@bp.before_request
def before_request():
    try:
        bearer = request.headers.get('authorization', request.headers.get('Authorization', None))
        g.logs = {'post_data': dict(request.values), 'req_header': {**request.headers}}
        g.token = bearer.split(" ")[-1] if bearer is not None else request.headers.get('jtoken', request.headers.get('Jtoken', None))
        g.token = g.token if g.token is not None else ''
        if g.token == '':
            return {'status' : 'error','error_description': 'Unauthorized Access'}, 401
        did = request.headers.get('device-security-id', request.headers.get('Device-security-id', request.headers.get('Device-Security-Id', None)))
        if did is None:
            return {'status' : 'error', 'error_description': 'Device id is required'}, 401
        
        jwt_res = jwt.decode(g.token, CONFIG['JWT_SECRET'], audience='DIGILOCKER', algorithms=['HS256'])
        data = jwt_res.get('data')
        
        # validating did
        if data.get('didsign') and len(data.get('didsign'))>20:
            dec_did = aes_decryption(data.get('didsign'), secret)
        
        if type(dec_did) == type({}) and dec_did.get('error'):
            return dec_did, 400
            
        if dec_did and dec_did != hashlib.md5(did.encode()).hexdigest():
            return {'status' : 'error', 'error_description':'Invalid device id provided.'}, 401
        
        g.ktype= request.headers.get("K-TYPE", None)
        g.hash= request.headers.get("X-VALUE", None)
        
        if g.ktype== "r" :
            g.skey= apk_sign_key_hash["r_key"]
        elif g.ktype== "d" or g.ktype== "ed":
            g.skey= apk_sign_key_hash["d_key"] 
        elif g.ktype== "er" :
            g.skey= apk_sign_key_hash["er_key"]

        g.digilockerid = data.get('digilockerid')      
        if g.digilockerid is None:
            log_data = {'status':'error','error_description':'lockerid not found','status_code':400}
            rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
            return {'status' : 'error', 'error_description' : 'Some technical error occurred'}, 400
        
    except Exception as e:
        log_data = {'status':'error','error_description':str(e),'status_code':401}
        rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
        return {'status' : 'error','error_description': 'Unauthorized Access'}, 401
        
@bp.route('validate/pin/v2', methods = ['POST'])
def validate_pin_v2():
    request_data= request.data
    crypt= Crypt(g.skey)
    try:
        if request_data is None or str(request_data) == "":
            res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Invalid request."})
            status_code, response= crypt.enc_aes_cbc_256(res_data)        
            g.xval= ''
            return response, 400
        
        data= request_data.decode('utf-8')    
        status_code, dec_data= crypt.dec_aes_cbc_256(data)    
        if status_code!= 200:
            res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorized request data"})
            status_code, response= crypt.enc_aes_cbc_256(res_data)
            g.xval= ''
            return response, 400
        
        status_code, req_hash= crypt.make_sha_256_hash(dec_data)
        if g.hash != req_hash :
            res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Request from unauthorized source."})
            status_code, response= crypt.enc_aes_cbc_256(res_data)
            g.xval= ''
            return response, 400
        
        req_json= json.loads(dec_data)
        txn=  req_json.get("txn", None)
        
        if  txn is None or txn== "":
            res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Invalid transaction."})
            status_code, response= crypt.enc_aes_cbc_256(res_data)
            g.xval= ''
            return response, 400

        pin = req_json.get("pin", None) 
        if pin is None or len(pin)!=6 :
            return {'status' : 'error', 'error_description':'Please enter valid pin.'}, 400
        
        user_data = get_users(g.digilockerid)
        pin_from_db =  user_data.get('pin')
        if pin_from_db is None or len(pin_from_db) <10:
                return {'status':'error', 'error_description':'Some technical error occurred'}, 400
        else:
            valid_pin, code = verify_pin(pin,pin_from_db)
            valid_pin["txn"] = txn
            status_code, g.xval= crypt.make_sha_256_hash(json.dumps(valid_pin))            
            status_code, response= crypt.enc_aes_cbc_256(json.dumps(valid_pin))
            return response, status_code
           
    except Exception as e:
        log_data = {'status':'error','error_description':str(e),'status_code':400}
        rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
        return {'status':'error', 'error_description':str(e)}, 400


