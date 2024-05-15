import os
import jwt
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv
from flask import Blueprint, request, g
from lib.constants import *
from lib.validations import Validations
import bcrypt
from lib.mongolib import MongoLib
import base64
from lib.secretsmanager import SecretManager

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local


secret = bytes(CONFIG['JWT_SECRET'], 'utf-8')

from lib.commonlib import CommonLib

from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
rmq = RabbitMQTaskClientLogstash()

rmq_queue = 'ACS_api_logs_verify_pin'

MONGOLIB = MongoLib()
VALIDATIONS = Validations()

bp = Blueprint('authlib', __name__)

@bp.before_request
def before_request():
    try:
        bearer = request.headers.get('authorization', request.headers.get('Authorization', None))
        g.logs = {'post_data': dict(request.values), 'req_header': {**request.headers}}
        g.token = bearer.split(" ")[-1] if bearer is not None else request.headers.get('jtoken', request.headers.get('Jtoken', None))
        g.token = g.token if g.token is not None else ''
        if g.token == '':
            return {
            'status' : 'error',
            'error_description': 'Unauthorized Access'
                }, 401
        did = request.headers.get('device-security-id', request.headers.get('Device-security-id', request.headers.get('Device-Security-Id', None)))
        if did is None:
            return {
            'status' : 'error',
            'error_description': 'Device id is required'
                }, 401
        
        jwt_res = jwt.decode(g.token, CONFIG['JWT_SECRET'], audience='DIGILOCKER', algorithms=['HS256'])
        data = jwt_res.get('data')
        g.digilockerid = data.get('digilockerid')
        g.pin = request.values.get('pin')
        
        # validating did
        if data.get('didsign') and len(data.get('didsign'))>20:
            dec_did = aes_decryption(data.get('didsign'), secret)
        
        if type(dec_did) == type({}) and dec_did.get('error'):
            return dec_did, 400
            
        if dec_did and dec_did != hashlib.md5(did.encode()).hexdigest():
            return {
            'status' : 'error',
            'error_description':'Invalid device id provided.'
                }, 401
    
        g.pin = CommonLib.aes_decryption_v2(g.pin, g.digilockerid[:16]) if g.pin is not None else g.pin
        if g.pin is None or len(g.pin)!=6 :
            return {
            'status' : 'error',
            'error_description':'Please enter valid pin.'
                }, 400
        
        
        if g.digilockerid is None:
            log_data = {'status':'error','error_description':'lockerid not found','status_code':400}
            rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
            return {
                'status' : 'error',
                'error_description' : 'Some technical error occurred'
                }, 400
        
    except Exception as e:
        log_data = {'status':'error','error_description':str(e),'status_code':401}
        rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
        return {
            'status' : 'error',
            'error_description': 'Unauthorized Access'
                }, 401
        
   
@bp.route('/validate_pin', methods = ['POST'])
def validate_pin():
    try:
       user_data = get_users(g.digilockerid)
       pin_from_db =  user_data.get('pin')
       if pin_from_db is None or len(pin_from_db) <10:
            return {'status':'error', 'error_description':'Some technical error occurred'}, 400
       else:
            valid_pin, code = verify_pin(g.pin,pin_from_db)
            return valid_pin, code
           
    except Exception as e:
        log_data = {'status':'error','error_description':str(e),'status_code':400}
        rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
        return {'status':'error', 'error_description':str(e)}, 400
        
    
        
def get_users(user):
    try:
        res, code = MONGOLIB.accounts_eve_v2('users', {"digilockerid": user}, {})
        # print(res, code, 'from eve users table')

        if code == 200 and res.get('status') == 'success' and res.get('response') is not None:
            data = res.get('response')[0]
            return data
        else:
            return {}
    except Exception as e:
        log_data = {'status':'error','error_description':str(e),'status_code':400}
        rmq.log_stash_logeer({**log_data, **g.logs},rmq_queue)
        return {}
    
def verify_pin(user_defined_pin, db_pin):
    try:                    
        if len(db_pin) == 32:
            '''handle case where pin in db is md5'''
            hash = db_pin
        else:
            hash = db_pin.split('|')[1] #this is db pin
        if password_verify(user_defined_pin, hash) == True:
            return {'status':'success'}, 200
        else:
            return {'status': 'error', 'error_description':'Please enter correct PIN.'}, 400
        
    except Exception as e:
            return {'status':'error', 'error_description':str(e)}

def password_verify(password, hash):
    try:
        if len(hash) == 32 and hash == hashlib.md5(password.encode('utf-8')).hexdigest():
            return True
        elif len(hash) > 32:
            compare = bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))
            return (compare == True)
        return False
    except Exception as e:
        return False
    
def aes_decryption(filtered_cipher_text, secret_key):
    try:
        filtered_cipher_text = filtered_cipher_text.replace('---', '+')
        iv = bytes(16 * '\x00', 'utf-8')
        encode_cipher = base64.b64decode(filtered_cipher_text)
        aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
        return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
    except Exception as e:
        return {"status": "error", "error_description": 'decryption:: ' + str(e)}
    