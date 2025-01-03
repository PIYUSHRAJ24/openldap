import base64
import hashlib
import jwt
from lib.constants import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lib.commonlib import CommonLib
from lib.validations import Validations
from lib.mongolib import MongoLib
import time
import secrets
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from lib.redislib import RedisLib


REDISLIB = RedisLib()
COMMONLIB = CommonLib()
VALIDATIONS = Validations()
MONGOLIB = MongoLib()

jwt_config = CONFIG['jwt']
SRT = "AAAAAAAAAAABBBBBBBBBBBBBB"

class DriveJwt:

    def __init__(self, request, conf):
        self.config = conf
        self.jwt_secret = self.config.get("JWT_SECRET")
        self.aes_secret = bytes(self.config.get("JWT_SECRET"), 'utf-8')
        bearer = request.headers.get('authorization', None)
        jwt_token = bearer.split(" ")[-1] if bearer is not None else None
        get_path = COMMONLIB.filter_path(request.args.get('path'))
        post_path = COMMONLIB.filter_path(request.values.get('path'))
        path = post_path if post_path else get_path
        token = jwt_token if jwt_token is not None else request.headers.get('jtoken')
        device_security_id = request.headers.get('device-security-id')
        self.jwt_token = token
        self.device_security_id = device_security_id
        self.path = path
        self.org_id = ''
        self.digilockerid = ''
        self.user_role = ''
        self.org_access_rules = []
        self.org_user_details = {}
        self.dept_details = {}
        self.sec_details = {}
        self.rs = RedisLib()

    def _pads(self, s):
        bs = AES.block_size  # AES.block_size is 16 bytes
        padding = bs - len(s) % bs
        return s + (chr(padding) * padding)

    def _pad(self, s):
        try:
            bs = AES.block_size
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return Errors.error('err_1201')+'[#1000]'

    def aes_encryption(self, raw,secret_key):
        try:
            raw = self._pad(raw)
            iv = bytes(16 * '\x00', 'utf-8')
            #iv = bytes(16)
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)
            return base64.b64encode(cipher.encrypt(raw.encode())).decode('utf-8').replace('+', '---')
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return Errors.error('err_1201')+"[#1001]"


    @staticmethod
    def aes_decryption(filtered_cipher_text, secret_key):
        try:
            iv = bytes(16 * '\x00', 'utf-8')
            encode_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
        except Exception as e:
            VALIDATIONS.log_exception(e)
            print({STATUS: ERROR, ERROR_DES: 'Exception:DriveJwt:aes_decryption:: ' + str(e)})
            return Errors.error('err_1201')+"[#1002]"
    
    def jwt_logout(self):
        try:
            #check if invlid token 
            token = self.jwt_token    
            device_security_id = self.device_security_id
            hash_jwt = hashlib.sha256(token.encode()).hexdigest()
            hash_did = hashlib.sha256(device_security_id.encode()).hexdigest()
      
            key = 'INVALID_JWT_'+hash_did+'_'+hash_jwt 
            self.rs.set(key, 'Invalid', 2592000)
            return {STATUS: "success"}, 401
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#2002]"}, 401
    
    
    def jwt_generate(self, digilockerid, did, orgid, source='web'):
        '''digilockerid, did, orgid, source'''
        try:
            query = {'org_id': orgid}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_176')}, 401
            if status_code != 200 or type(res[RESPONSE]) != type([]):
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155')}, 401
            self.org_access_details = res[RESPONSE]
            if self.org_access_details:
                rule = self.org_access_details[0]  
                is_active = rule.get('is_active') or 'N'
                is_approved = rule.get('is_approved') or 'N'
                if is_active is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_215')}, 400
                if is_approved is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_215')}, 400
            if did is None or did == '':
                return {"status": "error", "error_description": 'Missing device security id'}, 400
            secret = self.aes_secret
            ts = int(time.time())
            genreftoken = self.generate_refresh_token(digilockerid)
            access_token = {
                "iss":"https://digilocker.gov.in",
                "aud":"DIGILOCKER",
                "iat":ts,
                "nbf":ts - 60,
                "exp":ts + int(jwt_config.get('jwt_valid_upto') or 1800),
                "data":{
                    "status":"success",
                    "orgid":orgid,
                    "username":self.aes_encryption(digilockerid, secret),
                    "digilockerid":digilockerid,
                    "didsign":self.aes_encryption(did, secret),
                    "is_active":self.aes_encryption(is_active,secret),
                    "is_approved":self.aes_encryption(is_approved,secret),
                    "device-security-id":did

                    }
            }
            payload = {
              "access_token": access_token,
              "refresh_token": genreftoken,
              "token_type": "Bearer"
            }

            if source == 'M':
                payload["exp"] = ts + int(jwt_config.get('jwt_valid_upto_mobile') or 1800)
            encoded = jwt.encode(access_token, self.jwt_secret, algorithm="HS256")
            # encoded1 = jwt.encode(access_token, self.jwt_secret, algorithm="HS256")
            return {"status": "success", "token": encoded} , 200
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {"status": "error", "response": Errors.error('err_1201')+"[#1003]"}, 400

    def jwt_login(self):
        try:
            if not bool(int((jwt_config['jwt_enabled']))):
                return jwt_config['default_dir_s3'], 200
            token = self.jwt_token
            if token is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_107")}, 401

            jwt_res = jwt.decode(token, self.jwt_secret, audience='DIGILOCKER', algorithms=['HS256'])

            data = jwt_res.get('data', {})
            enc_username = data.get('username', '')
            self.org_id = data.get('orgid', '')
            self.digilockerid = data.get('digilockerid', '')
            enc_is_active = data.get('is_active', '')
            enc_is_approved = data.get('is_approved', '')
            username = self.aes_decryption(enc_username.replace('---', '+'), self.aes_secret)

            is_active = self.aes_decryption(enc_is_active.replace('---', '+'), self.aes_secret)
            is_approved = self.aes_decryption(enc_is_approved.replace('---', '+'), self.aes_secret)
            if is_active == 'N' and is_approved == 'PENDING':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_108")+"[#111]"}, 401
            
            did_sign = None
            did = None
            if data.get('didsign'):
                did_sign_enc = data.get('didsign', '')
                did_sign = self.aes_decryption(did_sign_enc.replace('---', '+'), self.aes_secret)
            device_security_id = self.device_security_id
            if device_security_id:
                # Calculate the sha256 hash
                sha256_result = hashlib.sha256(device_security_id.encode()).hexdigest()
                # Calculate the md5 hash
                md5_result = hashlib.md5(device_security_id.encode()).hexdigest()

                # Check if did_sign contains either sha256 or md5 hash
                if did_sign and (did_sign.find(sha256_result) == -1 and did_sign.find(md5_result) == -1):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_108")}, 401

            folder = self.path
            path = self.org_id + '/files/'  # this has been done as to create path based on org_id
            if folder:
                path += folder + '/'
            return path, 200
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+'[#1004]'}, 401
            # return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_206'), RESPONSE: 'DriveJwt:jwt_login:: ' + str(e)}, 401

    def jwt_login_org(self):
        try:
            path, code = self.jwt_login()
            if code != 200:
                return path, code
            if not self.digilockerid or not VALIDATIONS.is_valid_did(self.digilockerid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 401
            role, code = self.get_role()
            if code != 200:
                return role, code
            dept, code = self.get_dept_detail()
            if code != 200:
                return dept, code
            sec, code = self.get_sec_detail()
            if code != 200:
                return sec, code
            return path, 200
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+'[#1005]'}, 401
            # return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_206'), RESPONSE: 'DriveJwt:jwt_login_org:: ' + str(e)}, 401

    def get_role(self):
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        if status_code == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_176')}, 401
        if status_code != 200 or type(res[RESPONSE]) != type([]):
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155')}, 401
        self.org_access_rules = res[RESPONSE]
        access_id = hashlib.md5((self.org_id + self.digilockerid).encode()).hexdigest()
        access_id1 = hashlib.md5((self.org_id + self.digilockerid + self.org_id).encode()).hexdigest()  # defualt Manager
        for u in res[RESPONSE]:
            if u.get('access_id') == access_id or u.get('access_id') == access_id1:  # type: ignore
                self.org_user_details = u
        if self.org_user_details == {}:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_152')}, 401
        if self.org_user_details.get('is_active') != "Y":  # type: ignore
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_153')}, 401
        self.user_role = self.org_user_details.get('rule_id')  # type: ignore
        return self.org_user_details, 200  # type: ignore

    def get_dept_detail(self):

        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"], query, {"dept_id":1, "name":1, "description":1, "is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.dept_details = {d["dept_id"]:d for d in res[RESPONSE]}
        return self.dept_details, 200

    def get_sec_detail(self):
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], query, {"sec_id":1, "dept_id":1, "name":1, "description":1, "is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.sec_details = {d["sec_id"]:d for d in res[RESPONSE]}
        return self.sec_details, 200

    def generate_refresh_token(self, user_id):
        refresh_token = secrets.token_hex(32)
        expiration = jwt_config.get('refresh_valid_upto') or 30
        REDISLIB.set('refresh_token_'+user_id, refresh_token, int(expiration) * 24 * 60 * 60)
        return refresh_token

    def refresh_jwt(self, refresh_token, digilockerid, did, orgid, source):
        try:
            user_id = digilockerid
            stored_refresh_token = REDISLIB.get('refresh_token_'+user_id)
            if stored_refresh_token and stored_refresh_token == refresh_token:
                new_jwt_token = self.jwt_generate(digilockerid, did, orgid, source)
                new_refresh_token = self.generate_refresh_token(user_id)
                payload = {
                  "access_token": new_jwt_token,
                  "refresh_token": new_refresh_token,
                  "token_type": "Bearer"
                }

                return payload, 200
            else:
                return {STATUS: ERROR, ERROR_DES: "Invalid refresh token"}, 401
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+'[#1006]'}, 500
