import base64
import hashlib
import jwt
from lib.constants import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lib.commonlib import CommonLib
from lib.secretsmanager import SecretManager
from lib.validations import Validations
from lib.mongolib import MongoLib
from lib.redislib import RedisLib

COMMONLIB = CommonLib()
VALIDATIONS = Validations()
MONGOLIB = MongoLib()

secrets = SecretManager.get_secret()

jwt_config = CONFIG['jwt']

secrets = json.loads(SecretManager.get_secret())
try:
    secret = secrets.get('aes_secret', jwt_config['jwt_secret']) # default for local
except Exception as s:
    secret = os.getenv('JWT_SECRET') # for local


class DriveJwt:
    def __init__(self, request):
        bearer = request.headers.get('authorization', None)
        jwt_token = bearer.split(" ")[-1] if bearer is not None else None
        get_path = COMMONLIB.filter_path(request.args.get('path'))
        post_path = COMMONLIB.filter_path(request.values.get('path'))
        path = post_path if post_path else get_path
        token = jwt_token if jwt_token is not None else request.headers.get(
            'jtoken')
        device_security_id = request.headers.get('device-security-id')
        self.jwt_token = token
        self.device_security_id = device_security_id
        self.path = str(path)
        self.org_id = ''
        self.digilockerid = ''
        self.dept_id = request.form.get('dept_id','')
        self.user_role = ''
        self.org_access_rules = []
        self.org_user_details = {}
        self.user_rules = []
        self.user_departments = []
        self.user_sections = []
        self.dept_details = {}
        self.sec_details = {}
        self.org_access_functions = {}
        self.org_ds_fn_roles = {}
        self.aes_secret = bytes(secret, 'utf-8')
        self.rs = RedisLib()

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
            
            jwt_res = jwt.decode(token, secret, audience='DIGILOCKER', algorithms=['HS256'])
            
            data = jwt_res.get('data', {})
            enc_username = data.get('username', '')
            self.org_id = data.get('orgid', '')
            self.digilockerid = data.get('digilockerid', '')
            if not self.org_id or not VALIDATIONS.is_valid_did(self.org_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 401
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
            return {STATUS: ERROR, ERROR_DES: 'Exception:DriveJwt:jwt_login:: ' + str(e)}, 401

    def jwt_login_org(self):
        try:
            path, code = self.jwt_login()
            if code != 200:
                return path, code
            if not self.digilockerid or not VALIDATIONS.is_valid_did(self.digilockerid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 401
            # role, code = self.get_role()
            # if code != 200:
            #     return role, code
            # prmsion, code = self.get_permission()
            # if code != 200:
            #     return prmsion, code
            # ds_fn_roles, code = self.get_ds_fn_roles()
            # if code != 200:
            #     return ds_fn_roles, code
            # dept, code = self.get_dept_detail()
            # if code != 200:
            #     return dept, code
            # sec, code = self.get_sec_detail()
            # if code != 200:
            #     return sec, code
            # rs, code = self.get_redis_dept()
            # if code != 200:
            #     return rs, code
            # rss, code = self.get_redis_sec()
            # if code != 200:
            #     return rss, code
            return path, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:DriveJwt:jwt_login_org:: ' + str(e)}, 401

    # def get_role(self):
        
    #     query = {'org_id':self.org_id}
    #     res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        
    #     if status_code == 400:
    #         return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_185')}, 401
    #     if status_code != 200 or type(res[RESPONSE]) != type([]):
    #         return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164')}, 401
    #     self.org_access_rules = res[RESPONSE]

    #     default_access_id = hashlib.md5((self.org_id+self.digilockerid).encode()).hexdigest()
    #     for u in self.org_access_rules:
    #         if u.get('digilockerid') == self.digilockerid:
    #             if u.get('access_id') == default_access_id:
    #                 if u.get('is_active') != "Y":
    #                     return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_180')}, 401
    #                 self.user_role = u.get('rule_id')
    #                 self.org_user_details = u
    #             if u.get("is_active") == "Y" and u.get("dept_id") and not u.get('sec_id'):
    #                 self.user_departments.append(u['dept_id'])
    #             if u.get("is_active") == "Y" and u.get("sec_id"):
    #                 self.user_sections.append(u['sec_id'])
    #             self.user_rules.append(u)
    #     if not self.user_role:
    #         return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_161')}, 401
    #     return self.org_user_details, 200 #type: ignore
    
    # def get_permission(self):

    #     res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_func"], {}, {"fn_id":1,"fn_name":1,"fn_description":1}, limit=500)
    #     if status_code != 200 or type(res[RESPONSE]) == type([]):
    #         self.org_access_functions ={a['fn_name']:{"fn_id": a['fn_id'], "fn_description":a['fn_description']} for a in res[RESPONSE]}
    #     return self.org_access_functions, 200
    
    # def get_ds_fn_roles(self):
        
    #     query = {'org_id': self.org_id}
    #     res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_fu_roles"], query, {}, limit=500)
    #     if status_code != 200 or type(res[RESPONSE]) == type([]):
    #         self.org_ds_fn_roles = res[RESPONSE]
    #     return self.org_ds_fn_roles, 200 #type: ignore

    # def get_dept_detail(self):

    #     query = {'org_id': self.org_id}
    #     res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"], query, {"created_by":1, "dept_id":1,"name":1,"updated_on":1, "description":1}, limit=500)
    #     if status_code == 200 or type(res[RESPONSE]) == type([]):
    #         self.dept_details = {d["dept_id"]:d for d in res[RESPONSE]}  
    #     return self.dept_details, 200
    
    # def get_sec_detail(self):
        
    #     query = {'org_id': self.org_id}
    #     res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], query, {"created_by":1, "sec_id":1,"dept_id":1,"updated_on":1, "name":1,"description":1}, limit=500)
    #     if status_code == 200 or type(res[RESPONSE]) == type([]):
    #         self.sec_details = {d["sec_id"]:d for d in res[RESPONSE]}
    #     return self.sec_details, 200
   
    # def get_redis_dept(self):
    #     try:
    #         # Retrieve cached organization structure from Redis
    #         res = self.rs.get(self.org_id + '_org_structure')
    #         if res is not None:
    #             return json.loads(res), 200

    #         department_list = []

    #         for dept_id, dept_info in self.dept_details.items():
    #             # Initialize sections list for the department
    #             sections_list = []

    #             # Fetch profile details
    #             created_by = dept_info.get("created_by", "")
    #             profile = COMMONLIB.get_profile_details({'digilockerid': created_by})

    #             # Collect sections for the department
    #             for section_id, section_info in self.sec_details.items():
    #                 if section_info.get('dept_id') == dept_id:
    #                     sections_list.append(section_info)

    #             # Restructure department info
    #             dept_info_restructured = {
    #                 "created_by": dept_info.get("created_by", ""),
    #                 "dept_id": dept_id,
    #                 "name": dept_info.get("name", ""),
    #                 "photo": profile.get("photo", ""),
    #                 "updated_on": dept_info.get("updated_on", ""),
    #                 "username": profile.get("username", ""),
    #                 "sections": sections_list
    #             }
    #             department_list.append(dept_info_restructured)

    #         # Store the restructured department data in Redis
    #         self.rs.set(self.org_id + '_org_structure', json.dumps(department_list))

    #         return department_list, 200
    #     except Exception as e:
    #         return {"error": str(e)}, 500

    # def get_redis_sec(self):
    #     # Retrieve cached department structure from Redis
    #     res = self.rs.get(self.org_id+'_'+self.dept_id+'_dept_structure')
    #     if res is not None:
    #         return json.loads(res), 200

    #     # Build the sections list with matching dept_id
    #     sections = []
    #     for sec_id, sec_info in self.sec_details.items():
    #         if self.dept_id == sec_info.get("dept_id"):
                
    #              # Fetch profile details
    #             created_by = sec_info.get("created_by", "")
    #             profile = COMMONLIB.get_profile_details({'digilockerid': created_by})
                
    #             section = {
    #                 "created_by": sec_info.get("created_by", ""),
    #                 "name": sec_info.get("name", ""),
    #                 "photo": profile.get("photo", ""),
    #                 "sec_id": sec_id,
    #                 "updated_on": sec_info.get("updated_on", ""),
    #                 "username": profile.get("username", "")
    #             }
    #             sections.append(section)

    #     # Store the restructured department data in Redis
    #     self.rs.set(self.org_id+'_'+self.dept_id+'_dept_structure', json.dumps(sections))

    #     return sections, 200
