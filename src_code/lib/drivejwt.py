import base64
import hashlib
import jwt
from lib.constants import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lib.commonlib import CommonLib
from lib.validations import Validations
from lib.mongolib import MongoLib

COMMONLIB = CommonLib()
VALIDATIONS = Validations()
MONGOLIB = MongoLib()

jwt_config = CONFIG['jwt']


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
        

    @staticmethod
    def aes_decryption(filtered_cipher_text, secret_key):
        try:
            iv = bytes(16 * '\x00', 'utf-8')
            encode_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
        except Exception as e:
            print({STATUS: ERROR, ERROR_DES: 'Exception:DriveJwt:aes_decryption:: ' + str(e)})
            return ''

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
            username = self.aes_decryption(enc_username.replace('---', '+'), self.aes_secret)
            did_sign = None
            did = None
            if data.get('didsign'):
                did_sign_enc = data.get('didsign', '')
                did_sign = self.aes_decryption(did_sign_enc.replace('---', '+'), self.aes_secret)
            device_security_id = self.device_security_id
            if device_security_id:
                result = hashlib.md5(device_security_id.encode())
                did = result.hexdigest()
            if did_sign and (did is None or did_sign.find(did) == -1):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_108")}, 401
            folder = self.path
            path = self.org_id + '/files/' #this has been done as to create path based on org_id
            if folder:
                path += folder + '/'
            return path, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_206'), RESPONSE: 'DriveJwt:jwt_login:: ' + str(e)}, 401

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
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_206'), RESPONSE: 'DriveJwt:jwt_login_org:: ' + str(e)}, 401

    def get_role(self):
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        if status_code == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_176')}, 401
        if status_code != 200 or type(res[RESPONSE]) != type([]):
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155')}, 401
        self.org_access_rules = res[RESPONSE]
        access_id = hashlib.md5((self.org_id+self.digilockerid).encode()).hexdigest()
        for u in res[RESPONSE]:
            if u.get('access_id') == access_id: #type: ignore
                self.org_user_details = u
        if self.org_user_details == {}:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_152')}, 401
        if self.org_user_details.get('is_active') != "Y": #type: ignore
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_153')}, 401
        self.user_role = self.org_user_details.get('rule_id') #type: ignore
        return self.org_user_details, 200 #type: ignore
    
    def get_dept_detail(self):

        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"], query, {"dept_id":1,"name":1,"description":1,"is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.dept_details = {d["dept_id"]:d for d in res[RESPONSE]}  
        return self.dept_details, 200
    
    def get_sec_detail(self):
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], query, {"sec_id":1,"dept_id":1,"name":1,"description":1,"is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.sec_details = {d["sec_id"]:d for d in res[RESPONSE]}
        return self.sec_details, 200
