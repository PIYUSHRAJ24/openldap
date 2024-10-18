import base64
import hashlib
import jwt
import requests
from lib.constants_auth import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lib.commonlib_auth import CommonLib
from lib.secretsmanager import SecretManager
from lib.validations_auth import Validations
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
        self.pool_users_details = {}
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
            VALIDATIONS.log_exception(e)
            print({STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#2000]"})
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
            enc_is_active = data.get('is_active', '')
            enc_is_approved = data.get('is_approved', '')
            self.org_id = data.get('orgid', '')
            self.digilockerid = data.get('digilockerid', '')
            if not self.org_id or not VALIDATIONS.is_valid_did(self.org_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 401
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
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#2001]"}, 401

    
    def jwt_login_org(self):
        try:
            #check if invlid token 
            token = self.jwt_token    
            device_security_id = self.device_security_id
            hash_jwt = hashlib.md5(token.encode()).hexdigest()       
            hash_did = hashlib.md5(device_security_id.encode()).hexdigest()       
            key = 'INVALID_JWT_'+hash_did+'_'+hash_jwt # this is set in logout from misc api in redis
            res = self.rs.get(key)
            if res == 'Invalid':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_108")}, 401               
            
            
            path, code = self.jwt_login()
            if code != 200:
                return path, code
            if not self.digilockerid or not VALIDATIONS.is_valid_did(self.digilockerid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 401
            role, code = self.get_role()
            if code != 200:
                return role, code
            prmsion, code = self.get_permission()
            if code != 200:
                return prmsion, code
            ds_fn_roles, code = self.get_ds_fn_roles()
            if code != 200:
                return ds_fn_roles, code
            dept, code = self.get_dept_detail()
            if code != 200:
                return dept, code
            sec, code = self.get_sec_detail()
            if code != 200:
                return sec, code
            pool, code = self.get_pool_users_details()
            if code != 200:
                return pool, code
            rs, code = self.get_redis_dept()
            if code != 200:
                return rs, code
            rss, code = self.get_redis_sec()
            if code != 200:
                return rss, code
            return path, 200
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#2002]"}, 401

    def get_role(self):
        
        query = {'org_id':self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
        
        if status_code == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_185')}, 401
        if status_code != 200 or type(res[RESPONSE]) != type([]):
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164')}, 401
        self.org_access_rules = res[RESPONSE]

        default_access_id = hashlib.md5((self.org_id+self.digilockerid).encode()).hexdigest()
        default_access_id1 = hashlib.md5((self.org_id+self.digilockerid+self.org_id).encode()).hexdigest()
        for u in self.org_access_rules:
            if u.get('digilockerid') == self.digilockerid:
                if u.get('access_id') == default_access_id or u.get('access_id') == default_access_id1:
                    if u.get('is_active') != "Y":
                        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_180')}, 401
                    self.user_role = u.get('rule_id')
                    self.org_user_details = u
                if u.get("is_active") == "Y" and u.get("dept_id") and not u.get('sec_id'):
                    self.user_departments.append(u['dept_id'])
                if u.get("is_active") == "Y" and u.get("sec_id"):
                    self.user_sections.append(u['sec_id'])
                self.user_rules.append(u)
        if not self.user_role:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_161')}, 401
        return self.org_user_details, 200 #type: ignore
    
    def get_permission(self):

        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_func"], {}, {"fn_id":1,"fn_name":1,"fn_description":1}, limit=500)
        if status_code != 200 or type(res[RESPONSE]) == type([]):
            self.org_access_functions ={a['fn_name']:{"fn_id": a['fn_id'], "fn_description":a['fn_description']} for a in res[RESPONSE]}
        return self.org_access_functions, 200
    
    def get_ds_fn_roles(self):
        
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_fu_roles"], query, {}, limit=500)
        if status_code != 200 or type(res[RESPONSE]) == type([]):
            self.org_ds_fn_roles = res[RESPONSE]
        return self.org_ds_fn_roles, 200 #type: ignore

    def get_dept_detail(self):

        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_dept"], query, {"created_by":1, "dept_id":1,"name":1,"updated_on":1, "description":1,"is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.dept_details = {d["dept_id"]:d for d in res[RESPONSE]}  
        return self.dept_details, 200
    
    def get_sec_detail(self):
        
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_sec"], query, {"created_by":1, "sec_id":1,"dept_id":1,"updated_on":1, "name":1,"description":1,"is_active":1}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.sec_details = {d["sec_id"]:d for d in res[RESPONSE]}
        return self.sec_details, 200
    
    def get_pool_users_details(self):
        
        query = {'org_id': self.org_id}
        res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_users_pool"], query, {}, limit=500)
        if status_code == 200 or type(res[RESPONSE]) == type([]):
            self.pool_users_details = res[RESPONSE]
        return self.pool_users_details, 200
   
    def get_redis_dept(self):
        try:
            # Retrieve cached organization structure from Redis
            res = self.rs.get(self.org_id + '_org_structure')
            if res is not None:
                return json.loads(res), 200
            
            url = CONFIG["acsapi_dl"]["url"] + "/" + 'org/get_details'
            payload = {}
            headers = {
            'device-security-id': self.device_security_id,
            'Authorization': 'Bearer '+ self.jwt_token,
            'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.request("GET", url, headers=headers, data=payload)
            data_dict = response.json()
            if not data_dict.get('response'):
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_221')}, 400
            response_item = data_dict['response'][0]
            created_by_defualt = response_item.get('created_by', None)
            created_on_default = response_item.get('created_on', None)
            username = COMMONLIB.get_profile_details({'digilockerid': created_by_defualt}).get('username','')

            count_default = 0
            for rule in self.org_access_rules:
                if rule.get('user_type'):
                    count_default += 1
            
            department_list = []

            for dept_id, dept_info in self.dept_details.items():
                # Initialize sections list for the department
                sections_list = []
                count = 0
                for rule in self.org_access_rules:
                    if dept_id == rule.get('dept_id'):
                        count += 1
                
                # Fetch profile details
                created_by = dept_info.get("created_by", "")
                profile = COMMONLIB.get_profile_details({'digilockerid': created_by})

                # Collect sections for the department
                count_sec = 0
                for section_id, section_info in self.sec_details.items():
                    
                    if section_info.get('dept_id') == dept_id:
                        sections_list.append(section_info)
                        count_sec += 1
                

                # Restructure department info
                dept_info_restructured = {
                    "created_by": dept_info.get("created_by", ""),
                    "dept_id": dept_id,
                    "count": count,
                    "count_sec": count_sec,
                    "name": dept_info.get("name", ""),
                    "description": dept_info.get("description", ""),
                    "is_active": dept_info.get("is_active", ""),
                    "photo": profile.get("photo", ""),
                    "updated_on": dept_info.get("updated_on", ""),
                    "username": profile.get("username", ""),
                    "sections": sections_list
                }
                department_list.append(dept_info_restructured)
            department_list.append({
                "org_id": self.org_id,
                "dept_id": self.org_id, 
                "name": "Default",
                "is_active": "Y",
                "created_by": created_by_defualt,
                "count": count_default,
                "count_sec": "NA",
                "description": "Default Department of Organization",
                "photo": "NA",
                "updated_on": created_on_default,
                "username": username,
                "sections": "NA"
                                    
                })

            # Store the restructured department data in Redis
            self.rs.set(self.org_id + '_org_structure', json.dumps(department_list))
            return department_list, 200
        except Exception as e:
            VALIDATIONS.log_exception(e)
            return {"error": Errors.error('err_1201')+"[#2003]"}, 500

    def get_redis_sec(self):
        # Retrieve cached department structure from Redis
        res = self.rs.get(self.org_id+'_'+self.dept_id+'_dept_structure')
        if res is not None:
            return json.loads(res), 200

        # Build the sections list with matching dept_id
        sections = []
        for sec_id, sec_info in self.sec_details.items():
            count = 0
            for rule in self.org_access_rules:
            # Check if dept_id matches and sec_id exists but rule_id is None
                if sec_id == rule.get('sec_id') and sec_info.get("dept_id") == rule.get('dept_id') and rule.get('rule_id'):
                    count += 1
                count = count
            if self.dept_id == sec_info.get("dept_id"):
                
                 # Fetch profile details
                created_by = sec_info.get("created_by", "")
                profile = COMMONLIB.get_profile_details({'digilockerid': created_by})
                
                section = {
                    "created_by": sec_info.get("created_by", ""),
                    "name": sec_info.get("name", ""),
                    "count": count,
                    "description": sec_info.get("description", ""),
                    "is_active": sec_info.get("is_active", ""),
                    "photo": profile.get("photo", ""),
                    "sec_id": sec_id,
                    "updated_on": sec_info.get("updated_on", ""),
                    "username": profile.get("username", "")
                }
                sections.append(section)

        # Store the restructured department data in Redis
        self.rs.set(self.org_id+'_'+self.dept_id+'_dept_structure', json.dumps(sections))

        return sections, 200
