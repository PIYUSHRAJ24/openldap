import os
import jwt
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv
from lib.constants import CONFIG, ERROR, ERROR_DES
from api.accounts_profile import get_users
from api.accounts_profile import get_usersProfile

load_dotenv()

class ValidateUser:
    def __init__(self, request) :
        try:
            self.aes_secret = CONFIG['DEVICE_CRED'].get('JWT_SECRET')            
            self.status_code= 200
            res= {}
            if os.getenv("AUTH_MODE")== "OAUTH":
                digilocker_id= request.headers.get("digilockerid", request.headers.get("Digilockerid", ""))
                res= self.get_profile_data(digilocker_id)
            elif  os.getenv("AUTH_MODE")== "JTOKEN":                
                bearer= request.headers.get("authorization", request.headers.get("Authorization", None))                
                self.token= bearer.split(" ")[-1] if bearer is not None else request.headers.get("jtoken", request.headers.get('Jtoken', None))
                
                device_id= request.headers.get("device-security-id", request.headers.get("Device-security-id", request.headers.get("Device-Security-Id", None)))
                self.device_security_id= device_id if device_id else ""
                jwt_res= jwt.decode(self.token, bytes(self.aes_secret, 'utf-8'), audience='DIGILOCKER', algorithms=['HS256'])                
                self.validate_device_id(self.device_security_id, jwt_res.get("data"))
                
                '''call profile api and return data[uid_token_hash, username] based on above token'''
				# check for token then call below API using hmac method
                data= jwt_res.get("data")
                digilocker_id = data.get("digilockerid")
                res= self.get_profile_data(digilocker_id)
                
            if self.status_code==401 or res.get("lockerid")== None:
                self.status_code= 401
                
            self.uid_token= res.get("UID_Token")
            self.aadhaar_no = res.get("aadhaar")
            self.dateOfBirth = res.get("dateOfBirth")
            self.date_of_birth = res.get("date_of_birth")
            self.drive_migration= res.get("drive_migration")
            self.email= res.get("email")
            self.email_verified= res.get("email_verified")
            self.full_name = res.get("full_name")
            self.gender = res.get("gender")
            self.is_aadhaar_seeded= res.get("isAadhaarSeeded")
            self.is_account_verified= res.get("isAccountVerified")
            self.is_kyc= res.get("is_kyc")
            self.lbsnaa= res.get("lbsnaa")
            self.locker_id = res.get("lockerid")            
            self.mobile_no = res.get("mobile")
            self.ref_key= res.get('refkey')
            self.resident_name= res.get("residentName")
            self.state= res.get("state")
            self.uid_token_hash = res.get("uid_token_hash")
            self.user_alias= res.get("user_alias")            
            self.user_id = res.get("user_id")
            self.user_name= res.get("user_name")
            self.user_type= res.get("user_type")
        except Exception as e :
            self.status_code = 410
            self.excp_msg = str(e)            
    
    def get_profile_data(self, digilockerid):
        try:
            f_data = {}
            users = get_users(digilockerid, 'authenticator')
            if users.get('status') == 'error':
                return users
            
            f_data['UID_Token'] = users.get('uid_token')
            f_data['aadhaar'] = users.get('uid')
            f_data['drive_migration'] = users.get('drive_migration')
            f_data['email'] = users.get('email_id')
            f_data['email_verified'] = 'Y' if users.get('email_id_verified') == 1 else 'N'
            f_data['isAadhaarSeeded'] = 'Y' if users.get('user_type') in ['aadhaar', 'trusted_partners'] else 'N'
            f_data['isAccountVerified'] = 'Y' if users.get('user_type') in ['aadhaar','trusted_partners','non_aadhaar'] else 'N'
            f_data['is_kyc'] = f_data['isAadhaarSeeded']
            lb_list = os.getenv('allowd_lbsnaa_lockerid').split(',')
            f_data['lbsnaa'] = 'Y' if users.get('digilockerid') in lb_list else 'N'
            f_data['lockerid'] = users.get('digilockerid')
            f_data['mobile'] = users.get('mobile_no')
            f_data['refkey'] = users.get('uid')
            f_data['uid_token_hash'] = hashlib.md5(users.get('uid_token').encode('utf-8')).hexdigest() if users.get('uid_token') is not None else ''
            f_data['user_alias'] = users.get('user_alias')
            f_data['user_id'] = users.get('user_id')
            f_data['user_name'] = users.get('user_id')
            f_data['user_type'] = users.get('user_type')
            
            users_profile = get_usersProfile(digilockerid, 'authenticator')
            f_data['dateOfBirth'] = users_profile.get('date_of_birth')
            f_data['date_of_birth'] = users_profile.get('date_of_birth')
            f_data['full_name'] = users_profile.get('name')
            f_data['gender'] = users_profile.get('gender')
            f_data['residentName'] = users_profile.get('name')
            f_data['state'] = users_profile.get('state')
            return f_data
        except Exception as e:
            return {'status':'error', 'error_description':'Some technical error!'}            
     
    def validate_device_id(self, device_security_id, data):
        try:
            if device_security_id is None or len(device_security_id)==0:
                self.status_code= 401
                pass
            
            if data["didsign"] and len(data["didsign"]) > 20:
                dec_did= self.aes_decryption(data['didsign'], bytes(self.aes_secret, 'utf-8'))
            
            if dec_did and dec_did != hashlib.md5(device_security_id.encode()).hexdigest():
                self.status_code = 401
        except Exception as e:
            self.status_code = 401
    
    @staticmethod
    def aes_decryption(filtered_cipher_text, secret_key):
        try:
            filtered_cipher_text= filtered_cipher_text.replace("---", "+")
            iv= bytes(16 * '\x00', 'utf-8')
            encode_cipher= base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')                    
        except Exception as e:
            return 401, {ERROR: "error", ERROR_DES: 'Exception: in ValidateUser.aes_decryption:: ' + str(e)}
        
        
    def check_auth(self):
        try:            
            if self.status_code== 401:                
                return 401, {ERROR: "error", ERROR_DES: 'Unauthorised Access!'}
            if self.status_code== 410:                
                return 401, {ERROR: "error", ERROR_DES: self.excp_msg}            
            
            user_data= {
                "uid_token":self.uid_token,
                "aadhaar_no":self.aadhaar_no,
                "dateOfBirth":self.dateOfBirth,
                "date_of_birth":self.date_of_birth,
                "drive_migration":self.drive_migration,
                "email":self.email,
                "email_verified":self.email_verified,
                "full_name":self.full_name,
                "gender":self.gender,
                "is_aadhaar_seeded":self.is_aadhaar_seeded,
                "is_account_verified":self.is_account_verified,
                "is_kyc":self.is_kyc,
                "lbsnaa":self.lbsnaa,
                "locker_id":self.locker_id,
                "mobile_no":self.mobile_no,
                "ref_key":self.ref_key,
                "resident_name":self.resident_name,
                "state":self.state,
                "uid_token_hash":self.uid_token_hash,
                "user_alias":self.user_alias,
                "user_id":self.user_id,
                "user_name":self.user_name,
                "user_type":self.user_type
            }            
            return 200, user_data
        except Exception as e:
            return 401, {ERROR: "error", ERROR_DES: 'Exception:AuthLib:checkAuth:: ' + str(e)}
