import re
import hashlib
import time
from flask import url_for
from lib.constants_auth import *
import requests
import json
from Crypto.Cipher import AES
from lib.mongolib import MongoLib
from Crypto.Util.Padding import unpad
import base64
import jwt
from lib.secretsmanager import SecretManager

from lib.redislib import RedisLib
rs = RedisLib()
MONGOLIB = MongoLib()

jwt_config = CONFIG['jwt']
secrets = SecretManager.get_secret()

secrets = json.loads(secrets)
try:
    s = secrets.get('aes_secret', jwt_config['jwt_secret']) # default for local
except Exception as s:
    s = os.getenv('JWT_SECRET') # for local


class CommonLib:
    def __init__(self):
        self.active = True

    @staticmethod
    def aes_decryption(filtered_cipher_text, secret_key = s):
        try:
            iv = bytes(16 * '\x00', 'utf-8')
            encode_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key.encode('utf-8'), AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
        except Exception as e:
            return ''
    
    @staticmethod
    def filter_input(field):
        try:
            if not field:
                return field, 200
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\:\+\=\/]+'
            return re.sub(pat, "", field), 200
        except Exception as e:
            return 'Exception:CommonLib:filter_input:: ' + str(e), 400

    @staticmethod
    def filter_path(path):
        try:
            if path is None or path == '':
                return None
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\/\(\)]+'
            return re.sub(pat, "", path)
        except Exception as e:
            return 'Exception:CommonLib:filter_path:: ' + str(e), 400

    @staticmethod
    def filter_date(field):
        try:
            if field is None:
                return field, 200
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\:]+'
            return re.sub(pat, "", field), 200
        except Exception as e:
            return 'Exception:CommonLib:filter_date:: ' + str(e), 400
    
    @staticmethod
    def aes_decryption_v2(plain_text, secret):
        ''' This method introduced to decrypt using iv '''
        try:
            filtered_cipher_text = plain_text.replace('---', '+')
            secret_key=bytearray((hashlib.md5(secret.encode("utf-8")).hexdigest()).encode("utf-8"))
            iv = bytearray(secret.encode('utf-8'))
            encode_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
        except Exception as e:
            return None
        
    def isValidClientid(self, clientid):
        pattern = r'^[a-zA-Z0-9]{8}$'
        return re.match(pattern, clientid)

    def isValidTimestamp(self, ts):
        pattern = r'^[0-9]{10}$'
        return re.match(pattern, ts)

    def isValidhmac(self, hmac):
        pattern = r'^[a-zA-Z0-9]{64}$'
        return re.match(pattern, hmac)
   
    def check_hmac_expire(self, ts, hmac, plain_text):
        hmac_generated = hashlib.sha256(plain_text.encode()).hexdigest()
        expire_time = int(os.getenv('HMAC_EXPIRY')) + int(ts)

        if expire_time < int(time.time()):
            return {STATUS:ERROR, ERROR_DES: Errors.error('err_481')}, 400

        if hmac != hmac_generated:
            return {STATUS:ERROR, ERROR_DES: Errors.error('err_482')}, 400
        else:
            return True, 200

    def check_secret(self, user, clientid, ts, hmac):
        try:
            secret = self.get_secret(clientid) # implemented client secret from partner api TO-DO
            # secret = os.getenv('default_secret')
            plain_text = secret + clientid + user + ts
            return self.check_hmac_expire(ts, hmac, plain_text)
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_118")}, 400

    def get_secret(self, clientid):
        if os.getenv(clientid):
            return os.getenv(clientid)
        
        key = 'secret_' + clientid
        
        from_redis = rs.get(key)
        if from_redis is not None and len(from_redis)>0:
            return from_redis

        res = self.get_client_data(clientid)
        try:
            secret = res.get('client_secret')
            if secret is not None:
                rs.set(key, secret, 3600)
            return secret
        except Exception as e:
            # put logstash here-TO-DO
            return ''
        
    def get_client_data(self, clientid):
        try:
            ts = str(int(time.time()))
            
            url = os.getenv('auth_api_url') + clientid
            key = os.getenv('auth_key')
            org_id = os.getenv('org_id')
            
            plain_text = org_id + key + ts
            h_key = hashlib.sha256(plain_text.encode()).hexdigest()
            headers = {
            'uid': org_id,
            'ts': ts,
            'lockerreqesttoken': h_key
            }
            response = requests.request("GET", url, headers=headers)
            return json.loads(response.text)
        except Exception as e:
            # put logstash here-TO-DO
            return {}

    def validation_rules(self, request):
        try:
            user = request.values.get('user')
            clientid = request.values.get('clientid')
            ts = request.values.get('ts')
            hmac = request.values.get('hmac')

            if user is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_119")}, 400

            if clientid is None or self.isValidClientid(clientid) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_120")}, 400

            if ts is None or self.isValidTimestamp(ts) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_121")}, 400

            if hmac is None or self.isValidhmac(hmac) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_122")}, 400

            '''if input gets validated, call for hmac validation'''
            chk_hmac, code = self.check_secret(user, clientid, ts, hmac)
            if code == 200 and chk_hmac:
                return [user], 200
            else:
                return  chk_hmac, code

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_118")}, 400

    def UserAuthentication(self, client_id, hmac, digilockerid, ts):
        try:
            if client_id is None or hmac is None or digilockerid is None or ts is None:
                return 401, {STATUS: ERROR, ERROR_DES: 'Unauthorised Access'}

            # get hmac from data coming from client side
            key_received = hmac
            # creating hmac on server side stored secret
            plain_text_key_created = self.get_secret(client_id) + client_id + digilockerid + ts
            
            key_created = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            
            if key_received == key_created:
                return 200, {STATUS: SUCCESS, MESSAGE: 'Authenticated user found!'}
            else:
                return 401, {STATUS: ERROR, ERROR_DES: 'Unauthorised Access'}

        except Exception as e:
            return 400, {STATUS: ERROR, ERROR_DES: str(e)}
        
    '''Below method will validate token and return lockerid'''
    def validate_token(self, request):
        try:
            
            bearer = request.headers.get('authorization', request.headers.get('Authorization', None))
            token = bearer.split(" ")[-1] if bearer is not None else request.headers.get('jtoken', request.headers.get('Jtoken', None))
            token = token if token is not None else ''
            if token == '':
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
                
            jwt_res = jwt.decode(token, s, audience='DIGILOCKER', algorithms=['HS256'])
            data = jwt_res.get('data')
            # validating did
            if data.get('didsign') and len(data.get('didsign'))>20:
                dec_did = self.aes_decryption(data.get('didsign').replace('---', '+'))
            
            if type(dec_did) == type({}) and dec_did.get('error'):
                return dec_did, 400
            
            if dec_did and dec_did != hashlib.md5(did.encode()).hexdigest():
                return {
                'status' : 'error',
                'error_description':'Invalid device id provided.'
                    }, 401
            
            digilockerid = data.get('digilockerid')
            
            if digilockerid :
                return [digilockerid], 200
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111")}, 400

        except Exception as e:
            error_des = Errors.error("ERR_MSG_111")
            code = 400
            if str(e).find('Signature has expired') != -1:
                error_des = str(e)
                code = 401
            return {STATUS: ERROR, ERROR_DES: error_des}, code
        
    @staticmethod
    def get_profile_name(x):
        if x.get('digilockerid'):
            res = rs.get(x['digilockerid']+'_org_profile_details_eve')
            if res:
                return json.loads(res)
            res, status_code = MONGOLIB.accounts_eve_v2("users_profile", {"digilockerid": x['digilockerid']}, {}, limit=1)
            if status_code == 200:
                res = {'username': res[RESPONSE][0].get('name', ''), 'photo': ''} # type: ignore
                rs.set(x['digilockerid']+'_org_profile_details_eve', json.dumps(res))
                return res
        return {'username': '', 'photo': ''}
        
    @staticmethod
    def get_profile_details(x):
        if x.get('digilockerid'):
            res = rs.get(x['digilockerid']+'_org_profile_details')
            if res:
                return json.loads(res)
            client_id = 'EA98DD7F33'
            ts = str(int(time.time()))
            plain_text_key_created = CONFIG['credentials'].get(client_id, '') + client_id + x['digilockerid'] + ts
            hmac = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            post_data = {
                'clientid': client_id,
                'ts': ts,
                'user': x['digilockerid'],
                'hmac': hmac,
                'resident_photo': "yes"
            }
            res = requests.post('https://acsapi.dl6.in/profile/1.2', post_data)
            try:
                resp = json.loads(res.text)
                if res.status_code >= 200 and res.status_code < 300:
                    res = {'username': resp['full_name'], 'photo': resp['resident_photo']}
                    rs.set(x['digilockerid']+'_org_profile_details', json.dumps(res))
                    return res
                else: return CommonLib.get_profile_name(x)
            except Exception:
                pass
        return CommonLib.get_profile_name(x)