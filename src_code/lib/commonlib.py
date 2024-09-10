import datetime
import re
import hashlib, urllib
import time
from lib.constants import *
import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from flask import url_for, g
import jwt
from lib.mongolib import MongoLib
from assets.images import default_avatars
from flask import render_template, request
from thefuzz import fuzz
from lib.cryptographer import Crypt			

from lib.redislib import RedisLib
rs = RedisLib()
MONGOLIB = MongoLib()
SHARED_DOCS_D_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class CommonLib:
    def __init__(self, conf={}):
        self.config = conf
        self.jwt_secret = self.config.get("JWT_SECRET")
        self.clientid = None
    
    @staticmethod
    def aes_encryption(plain_text, secret_key):
        try:
            iv = bytearray(secret_key.encode('utf-8'))
            secret_key = hashlib.md5(secret_key.encode("utf-8")).hexdigest()
            cipher = AES.new(secret_key.encode('utf-8'), AES.MODE_CBC, iv)
            padded_plain_text = pad(plain_text.encode('utf-8'), AES.block_size)
            cipher_text = cipher.encrypt(padded_plain_text)
            return base64.b64encode(cipher_text).decode('utf-8')
        except Exception as e:
            return ''
        
    @staticmethod    
    def aes_encryption_v3(plain_text, secret):
        ''' This method introduced to encrypt using iv '''
        try:
            # Generate a 16-byte secret key using MD5 hash
            secret_key = hashlib.md5(secret.encode("utf-8")).digest()
            # Generate a 16-byte IV using MD5 hash
            iv = hashlib.md5(secret.encode('utf-8')).digest()
            
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            padded_plain_text = pad(plain_text.encode('utf-8'), AES.block_size)
            cipher_text = aes_obj.encrypt(padded_plain_text)
            encoded_cipher_text = base64.b64encode(cipher_text).decode('utf-8')
            filtered_cipher_text = encoded_cipher_text.replace('+', '---')
            return filtered_cipher_text
        except Exception as e:
            print(f"Error during encryption: {e}")
            return None
     
    @staticmethod   
    def aes_decryption_v3(cipher_text, secret):
        ''' This method introduced to decrypt using iv '''
        try:
            filtered_cipher_text = cipher_text.replace('---', '+')
            # Generate a 16-byte secret key using MD5 hash
            secret_key = hashlib.md5(secret.encode("utf-8")).digest()
            # Generate a 16-byte IV using MD5 hash
            iv = hashlib.md5(secret.encode('utf-8')).digest()
            
            encoded_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key, AES.MODE_CBC, iv)
            decrypted_padded_text = aes_obj.decrypt(encoded_cipher)
            plain_text = unpad(decrypted_padded_text, AES.block_size).decode('utf-8')
            return plain_text
        except Exception as e:
            print(f"Error during decryption: {e}")
            return None   
        
    @staticmethod
    def filter_cbse_input(field):
        try:
            if field is None:
                return field
            # pat = r'[\[\]\:=*?<>+&|^~+\"\']'
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\<\>\:\\\/\?\[\]\{\}\(\)]+'
            return re.sub(pat, "", field)
        except Exception as e:
            return str(e)
        
    @staticmethod
    def aes_decryption(filtered_cipher_text, secret_key):
        try:
            iv = bytes(16 * '\x00', 'utf-8')
            encode_cipher = base64.b64decode(filtered_cipher_text)
            aes_obj = AES.new(secret_key.encode('utf-8'), AES.MODE_CBC, iv)
            return unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
        except Exception:
            return ''
    
    @staticmethod
    def filter_input(field):
        try:
            if field is None:
                return field, 200
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\:\/\=\+]+'
            return re.sub(pat, "", field), 200
        except Exception as e:
            return 'Exception:CommonLib:filter_input:: ' + str(e), 400

    @staticmethod
    def filter_input_file_upload(str):
        try:
            field = urllib.parse.unquote(urllib.parse.unquote(str))
            if field is None:
                return field
            # pat = r'[\[\]\:=*?<>+&|^~+\"\']'
            pat = r'[^A-Za-z0-9\.\s\@\&\-\_\(\)]+'
            return re.sub(pat, "", field)
        except Exception as e:
            return str(e)

    def is_valid_did(self, id):
        pattern = r'^[a-zA-Z0-9\-]{36}$'
        return re.fullmatch(pattern, id)
    
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

    def isValidClientid(self, clientid):
        pattern = r'^[a-zA-Z0-9]{8}$'
        return re.match(pattern, clientid)

    def isValidTimestamp(self, ts):
        pattern = r'^[0-9]{10}$'
        return re.match(pattern, ts)

    def isValidhmac(self, hmac):
        pattern = r'^[a-zA-Z0-9]{64}$'
        return re.match(pattern, hmac)
    
    def is_valid_cin(self, code):
        pattern = r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$"
        return re.match(pattern, str(code))
    
    def isValidAadhaar(self, str):
        pattern = r'^[2-9]{1}[0-9]{11}$'
        return re.match(pattern, str)
    
    def isValidName(self, str):
        pattern = r'^[a-zA-Z]{4,}(?: [a-zA-Z]+){0,2}$'
        return re.match(pattern, str)
        
    def check_hmac_expire(self, ts, hmac, plain_text):
        hmac_generated = hashlib.sha256(plain_text.encode()).hexdigest()
        expire_time = int(os.getenv('HMAC_EXPIRY')) + int(ts)

        if expire_time < int(time.time()):
            return {'status': 'error', 'error_description': 'HMAC does not match.'}, 400

        if hmac != hmac_generated:
            return {'status': 'error', 'error_description': 'Invalid HMAC Provided.'}, 400
        else:
            return True, 200

    def check_secret(self, user, clientid, ts, hmac):
        try:
            secret = self.get_secret(clientid) # implemented client secret from partner api TO-DO
            # secret = os.getenv('default_secret')
            plain_text = secret + clientid + user + ts
            plain_text = plain_text.replace('"','') #added as if there is "
            return self.check_hmac_expire(ts, hmac, plain_text)
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_118"), 'err':str(e)}, 400
        
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

    def director_name_match(self, cin, din, did):
        try:
            if DEBUG_MODE:
                return {STATUS: SUCCESS, "match": 100}, 200
            res = rs.get(did+'_org_add_user_verify_otp')
            if not res:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_166'), RESPONSE: "is_valid_din: redis"}, 500
            name = json.loads(res).get('user_name','')
            url = CONFIG['mca']['din_url'] + cin
            headers = {
                'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
                'X-APISETU-CLIENTID': CONFIG['mca']['client_id']
            }
            response = requests.request("GET", url, headers=headers, timeout=30)
            original_name = ''
            try:
                res = json.loads(response.text)
            except Exception:
                res = {}
            if response.status_code == 200:
                is_valid_din = [d['din'] == din for d in res]
                if True in is_valid_din:
                    for i in res:
                        if i['din'] == din:
                            original_name = i['name']
                else:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164')}, 401
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: "din service failed. "+res.get('error', response.text)}, 501
            ratio = fuzz.ratio(name, original_name)
            token_set_ratio = fuzz.token_set_ratio(name, original_name)
            token_sort_ratio = fuzz.token_sort_ratio(name, original_name)
            if ratio >= token_set_ratio and ratio >= token_sort_ratio:
                match = ratio
            elif token_set_ratio >= ratio and token_set_ratio >= token_sort_ratio:
                match = token_set_ratio
            elif token_sort_ratio >= ratio and token_sort_ratio >= token_set_ratio:
                match = token_sort_ratio
            else:
                match = 0
            if match > 70:
                return {STATUS: SUCCESS, "match": match}, 200
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_165'), "match": match}, 400
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: "is_valid_din: " + str(e)}, 500

    def validation_rules(self, request, is_user = False):
        try:
            user = request.values.get('user') or request.headers.get('user', '')
            clientid = request.values.get('clientid') or request.headers.get('clientid')
            ts = request.values.get('ts') or request.headers.get('ts')
            hmac = request.values.get('hmac') or request.headers.get('hmac')

            if not is_user and user is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_119")}, 401

            if clientid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_120")}, 401

            if ts is None or self.isValidTimestamp(ts) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_121")}, 401

            if hmac is None or self.isValidhmac(hmac) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_122")}, 401

            '''if input gets validated, call for hmac validation'''
            chk_hmac, code = self.check_secret(user, clientid, ts, hmac)
            if code == 200 and chk_hmac:
                return [user, clientid], 200
            else:
                return  chk_hmac, code

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_118"), 'err':str(e)}, 400
    
    '''Validation for user login history'''
    def validation_rules_v1(self, request):
        try:
            ''' Validate hmac details received over http request '''
            clientid = request.headers.get("clientid")
            ts = request.headers.get("ts")
            hmac = request.headers.get("hmac")
            input_data = request.json
            user = input_data.get('lockerid')
            if user is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_119")}, 401

            if clientid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_120")}, 401
            if ts is None or self.isValidTimestamp(ts) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_121")}, 401
            if hmac is None or self.isValidhmac(hmac) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_122")}, 401

            '''if input gets validated, call for hmac validation'''

            chk_hmac, code = self.check_secret(user, clientid, ts, hmac)
            if code == 200 and chk_hmac:
                return [user], 200
            else:
                return  chk_hmac, code

        except Exception as e:
            print(str(e))
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_118"), 'err':str(e)}, 400
    
    def UserAuthentication(self, clientid,digilockerid,hmac,ts):
        try:    
            # '''to bypass authentication while local dev.'''
            # if os.getenv('APP_ENV') == 'LOCAL':
            #     return 200, {STATUS: SUCCESS, MESSAGE: 'Authenticated user found!'}
            if clientid is None or hmac is None or digilockerid is None or ts is None:
                return 401, {STATUS: ERROR, ERROR_DES: 'Unauthorised Access'}
            # get hmac from data coming from client side
            key_received = hmac
            # creating hmac on server side stored secret
            plain_text_key_created = self.get_secret(clientid + clientid + ts)
            
            # key_created = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            key_created = hashlib.sha256(plain_text_key_created)
            
            
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
                
            jwt_res = jwt.decode(token, self.jwt_secret, audience='DIGILOCKER', algorithms=['HS256'])
            data = jwt_res.get('data')
            # validating did
            if data.get('didsign') and len(data.get('didsign'))>20:
                dec_did = self.aes_decryption(data.get('didsign').replace('---', '+'), self.jwt_secret)
            
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
                res = {'username': res[RESPONSE][0].get('name', ''), 'photo': default_avatars.user, # type: ignore
                       'gender': None, 'email': None, 'mobile': None}
                rs.set(x['digilockerid']+'_org_profile_details_eve', json.dumps(res))
                return res
        return {'username': '', 'photo': default_avatars.user}

    @staticmethod
    def get_profile_details(x):
        if x.get('digilockerid'):
            res = rs.get(x['digilockerid']+'_org_profile_details')
            if res:
                return json.loads(res)
            client_id = CONFIG['acsapi']['client_id']
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
            res = requests.post(CONFIG['acsapi']['url']+'/profile/1.0', post_data)
            try:
                resp = json.loads(res.text)
                if res.status_code >= 200 and res.status_code < 300:
                    res = {
                        'username': resp['full_name'],
                        'photo': resp['resident_photo'] if resp['resident_photo'] else default_avatars.user,
                        'gender': resp['gender'] or None,
                        'email': resp['email'] or None,
                        'mobile': resp['mobile'] or None
                    }
                    rs.set(x['digilockerid']+'_org_profile_details', json.dumps(res))
                    return res
                else: return CommonLib.get_profile_name(x)
            except Exception:
                pass
        return CommonLib.get_profile_name(x)

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
    
    
    @staticmethod
    def validate_dateformat(valid_till):
        try:
            try:
                if valid_till == None or valid_till == '':
                    return 400, {"status": "error", "error_description": 'file_name cant be null'}
                valid_till = datetime.datetime.strptime(valid_till, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return  400, {"status": "error", "error_description": 'Incorrect valid_till format, should be YYYY-MM-DD H:M:S'}
            return 200, valid_till
        except Exception as e:
            return 400, {"status": "error", "error_description": "Some Technical error occured.", "res":'Exception:Commonlib:filter_path:: ' + str(e)+' [#107]'}
        

    def create_org_user(self, transaction_id, digilockerid):
        try:
            if not rs.get(transaction_id + '_org_signup_request'):
                res, status_code = MONGOLIB.org_eve("org_user_requests", {'transaction_id': transaction_id}, {})
                if status_code != 200:
                    return res, status_code

                if len(res[RESPONSE]) == 1:
                    if not res[RESPONSE][0].get('rejected_on'): # type: ignore
                        self.update_request(transaction_id, "expired", True)
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_175")}, 400
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 408

            res, status_code = MONGOLIB.org_eve("org_user_requests", {'transaction_id': transaction_id}, {})
            if status_code != 200:
                return res, status_code

            if len(res[RESPONSE]) == 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_173")}, 400
            elif len(res[RESPONSE]) > 1:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_174")}, 400

            if res[RESPONSE][0].get('rejected_on'): # type: ignore
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_178")%res[RESPONSE][0].get('request_status')}, 400 # type: ignore

            if res[RESPONSE][0].get('request_status') == "created": # type: ignore
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_179")}, 400

            access_post_data = {
                'org_id': res[RESPONSE][0]['org_id'], # type: ignore
                'digilockerid': digilockerid,
                'access_id': hashlib.md5((res[RESPONSE][0]['org_id']+digilockerid).encode()).hexdigest(), # type: ignore
                'is_active': 'Y',
                'rule_id': res[RESPONSE][0]['rule_id'], # type: ignore
                'designation': res[RESPONSE][0].get('designation'), # type: ignore
                'updated_by': res[RESPONSE][0].get('updated_by'), # type: ignore
                'updated_on': datetime.datetime.now().strftime(D_FORMAT)
            }
            if res[RESPONSE][0].get('dept_id','') == g.org_id:
                access_post_data['access_id'] = hashlib.md5((res[RESPONSE][0]['org_id']+digilockerid+res[RESPONSE][0]['org_id']).encode()).hexdigest()
                access_post_data['user_type'] = res[RESPONSE][0].get('user_type','')
            else:
                access_post_data['access_id'] = hashlib.md5((res[RESPONSE][0]['org_id']+digilockerid).encode()).hexdigest()

            cin = res[RESPONSE][0].get('cin') # type: ignore
            din = res[RESPONSE][0].get('din') # type: ignore
            
            # Account can only be associated with 5 Entities
            query = {'digilockerid': digilockerid}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
            if status_code == 500:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155')}, 400
            
            if status_code == 200 and len(res[RESPONSE]) > 0:
                active_users = []
                for a in res[RESPONSE]:
                    if a.get('is_active') == 'Y':
                        active_users.append(a)
                if len(active_users) > int(CONFIG['roles']['max_organizations']):
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_205')}, 400

            # Same accounts can not be added
            query = {'org_id': access_post_data['org_id']} # type: ignore
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_rules"], query, {}, limit=500)
            if status_code == 400:
                return render_template(FORCED_ACCESS_TEMPLATE), 401
            
            if status_code != 200 or type(res[RESPONSE]) != type([]):
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155')}, 401
            org_access_rules = res[RESPONSE]

            if digilockerid in [d['digilockerid'] for d in org_access_rules]: # type: ignore
                self.update_request(transaction_id, "duplicate", True)
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_156')}, 400

            if access_post_data['designation'] == "director" and self.is_valid_cin(cin):
                if not din[0] or len(din[0]) != 8:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_145")}, 400
                res, status_code = self.director_name_match(cin, din, digilockerid)
                if status_code != 200:
                    return res, status_code
            return {STATUS: SUCCESS, 'post_data': access_post_data, 'din': din}, 200 # type: ignore
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"),RESPONSE: 'Exception:Commonlib:create_org_user::' + str(e)}, 500


    def update_request(self, transaction_id, status:str, system = False):
        post_data = {
                'request_status': status,
                'rejected_by': "system" if system else g.digilockerid,
                'rejected_on': datetime.datetime.now().strftime(D_FORMAT),
            }
        res, code = MONGOLIB.org_eve_patch("org_user_requests/"+transaction_id, post_data)
        if code != 200:
            return res, code
        return {STATUS: SUCCESS, MESSAGE: "Request successfully %s."%status}, 200


    def validate_hmac(self, option):
        if option == "demoauth":
            return self.validate_demoauth()
        return {STATUS: ERROR, ERROR_DESCRIPTION: 'Unauthorized Access!'}, 401


    def validate_demoauth(self):
        hmac = request.headers.get('hmac')
        self.clientid = clientid = request.headers.get('clientid')
        ts = request.headers.get('ts')

        if not clientid:
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid Clientid provided.'}, 401
        
        if not ts or not self.isValidTimestamp(ts):
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid Timestamp provided.'}, 401
        
        uid = request.values.get('uid')
        uid_decrypted = CommonLib.aes_decryption_v2(uid, clientid+"X"*(16-len(clientid)))

        fullname = request.values.get('name')
        gender = request.values.get('gender')
        dob = request.values.get('dob')
        consent = request.values.get('consent')

        if not uid_decrypted or not self.isValidAadhaar(uid_decrypted):
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid Aadhaar provided.'}, 400
        
        if not fullname or not self.isValidName(fullname):
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid Name provided.'}, 400   
        
        if not dob:
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid DOB provided.'}, 400
        
        if not consent:
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid consent provided.'}, 400
        
        consent = consent.upper()
        if consent not in ('Y', 'N'):
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Consent should be either "Y" or "N".'}, 400
        
        secret = CONFIG['credentials'].get(clientid, '')
        plain_text = secret + clientid + ts + uid_decrypted + fullname + gender + dob + consent
        hmac_generated = hashlib.sha3_256(plain_text.encode()).hexdigest()
        expire_time = int(os.getenv('HMAC_EXPIRY')) + int(ts)
    
        if expire_time < int(time.time()):
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'HMAC does not match.'}, 401
        if not hmac or hmac != hmac_generated:
            return {STATUS: ERROR, ERROR_DESCRIPTION: 'Invalid HMAC Provided.'}, 401
 
        return {
            STATUS: SUCCESS,
           'data': {
                "clientid": clientid, 
                "uid" : uid_decrypted,
                "name" : fullname,
                "gender" : gender,
                "dob" : dob,
                "consent" : consent
            }
        }, 200

    
    def bulkShare_to_Individual(self, request):
        try:
            
            shared_files = request.json.get('shared_files',[])
            if not shared_files:
             return 400, {"status": "error", "error_description": "file request not found"}
         
            uid = self.filter_input(field=request.json.get('uid'))
            shared_by_name = self.filter_input(field=request.json.get('shared_by_name'))
            valid_till = self.filter_input(field=request.json.get('valid_till'))
            source = self.filter_input(field=request.json.get('source'))
            purpose = self.filter_input(field=request.json.get('purpose'))
            
            try:
                if uid[0] == 400:
                    return 400, {"status": "error", "error_description": "Unsupported character in %s.!" % "uid"}
                elif not uid[0]:
                    return 400, {"status": "error", "error_description": "Please enter uid"}
                adh = CommonLib.aes_decryption_v2(uid[0], g.org_id[:16])
                if len(adh) != 12:
                    return 400, {"status": "error", "error_description": "Please enter valid uid."}
                
                token = self.get_token(adh)
                if not token:
                    return 400, {"status": "error", "error_description": "We were unable to find any DigiLocker Account linked with this Aadhaar Number."}
                
                if shared_by_name[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_by_name."}
                elif shared_by_name[0] is None or shared_by_name[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter shared_by_name."}
    
                if valid_till[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid_till date."}
                elif valid_till[0] is None or valid_till[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter valid_till date."}
                
                if source[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter source (ids/drive)."}
                elif source[0] is None or source[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter source (ids/drive)."}
                elif source[0] not in ["ids", "drive"]:
                    return 400, {"status": "error", "error_description": "Source Type must be ids/drive."}
                
                if purpose[0] == 400:
                    return 400, {"status": "error", "error_description": "Please not define."}
                if purpose[0] is not None and len(purpose[0]) > 200:
                    return 400, {"status": "error", "error_description": "Purpose cannot be more than 200 characters."}
                
                for file in shared_files :
                    if not file.get('is_folder') :
                        return 400, {"status": "error", "error_description": "Please enter is_folder."}
                    elif file.get('is_folder') not in ["N", "Y"]:
                        return 400, {"status": "error", "error_description": "Folder Type must be N/Y."}
                                    
                    if not file.get('file_path'):
                        return 400, {"status": "error", "error_description": "Please enter file_path."}
                    elif file.get('file_path','').split("/")[0] != g.org_id and source[0] not in ["ids", "drive"]:
                        return 400, {"status": "error", "error_description": "You are not allowed to share document."}
        
                    if source[0] == 'ids' and not file.get('file_name'):
                        return 400, {"status": "error", "error_description": "Please enter file_name (ids)."}
              
            except Exception as e:
                return 400, {'status': 'error', 'error_description': str(e)+' [#305]'}
            
            return 200, [adh, shared_by_name[0], shared_files, valid_till[0], source[0], purpose[0]]
            
        except Exception as e:
            return 400, {'status': 'error', 'error_description': str(e)+' [#108]'}

    
    def bulkShareEntity_validation(self, request):
        try:
            
            shared_files = request.json.get('shared_files',[])
            if not shared_files:
             return 400, {"status": "error", "error_description": "file request not found"}
         
            shared_to_org_id = self.filter_input(field=request.json.get('shared_to_org_id'))
            shared_to_name = self.filter_input(field=request.json.get('shared_to_name')) 
            shared_by_name = self.filter_input(field=request.json.get('shared_by_name'))
            valid_till = self.filter_input(field=request.json.get('valid_till'))
            source = self.filter_input(field=request.json.get('source'))
            purpose = self.filter_input(field=request.json.get('purpose'))
            
            try:
                if shared_to_org_id[0] == 400:
                    return 400, {"status": "error", "error_description": "Unsupported character in %s.!" % "shared_to_org_id"}
                elif shared_to_org_id[0] is None or shared_to_org_id[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter shared_to_org_id."}
                elif self.is_valid_did(shared_to_org_id[0]) is None:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_to_org_id."}
                elif shared_to_org_id[0] == g.org_id:
                    return 400, {"status": "error", "error_description": "Sharing itself is not allowed."}

                if shared_to_name[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_to_name."}
                elif shared_to_name[0] is None or shared_to_name[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter shared_to_name."}
                if shared_by_name[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_by_name."}
                elif shared_by_name[0] is None or shared_by_name[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter shared_by_name."}
    
                if valid_till[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid_till date."}
                elif valid_till[0] is None or valid_till[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter valid_till date."}
                
                if source[0] == 400:
                    return 400, {"status": "error", "error_description": "Please enter source (ids/drive)."}
                elif source[0] is None or source[0] == "":
                    return 400, {"status": "error", "error_description": "Please enter source (ids/drive)."}
                elif source[0] not in ["ids", "drive"]:
                    return 400, {"status": "error", "error_description": "Source Type must be ids/drive."}
                
                if purpose[0] == 400:
                    return 400, {"status": "error", "error_description": "Please not define."}
                if purpose[0] is not None and len(purpose[0]) > 200:
                    return 400, {"status": "error", "error_description": "Purpose cannot be more than 200 characters."}
                
                for file in shared_files :
                    if not file.get('is_folder') :
                        return 400, {"status": "error", "error_description": "Please enter is_folder."}
                    elif file.get('is_folder') not in ["N", "Y"]:
                        return 400, {"status": "error", "error_description": "Folder Type must be N/Y."}
                                    
                    if not file.get('file_path'):
                        return 400, {"status": "error", "error_description": "Please enter file_path."}
                    elif file.get('file_path','').split("/")[0] != g.org_id and source[0] not in ["ids", "drive"]:
                        return 400, {"status": "error", "error_description": "You are not allowed to share document."}
        
                    if source[0] == 'ids' and not file.get('file_name'):
                        return 400, {"status": "error", "error_description": "Please enter file_name (ids)."}
              
            except Exception as e:
                return 400, {'status': 'error', 'error_description': str(e)+' [#305]'}
            
            return 200, [shared_to_org_id[0], shared_to_name[0], shared_by_name[0], shared_files, valid_till[0], source[0], purpose[0]]
            
        except Exception as e:
            return 400, {'status': 'error', 'error_description': str(e)+' [#108]'}

    def shared_by_me_list_val(self, request):
        try:
            shared_to = self.filter_input(field=request.values.get('shared_to'))
            path = self.filter_input(field=request.values.get('path'))
            try:
                if shared_to[1] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_to."}
                elif not shared_to[0]:
                    return 400, {"status": "error", "error_description": "Please enter shared_to."}
                elif not self.is_valid_did(shared_to[0]):
                    return 400, {"status": "error", "error_description": "Please enter valid shared_to."}
                if path[1] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid path."}
            except Exception as e:
                return 400, {'status': 'error', 'error_description': str(e)+' [#306]'}
            
            return 200, [shared_to[0], path[0]]
            
        except Exception as e:
            return 400, {'status': 'error', 'error_description': str(e)+' [#109]'}   
        
    def shared_to_me_list_val(self, request):
        try:
            shared_by = self.filter_input(field=request.values.get('shared_by'))
            path = self.filter_input(field=request.values.get('path'))
            try:
                if shared_by[1] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid shared_by."}
                elif not shared_by[0]:
                    return 400, {"status": "error", "error_description": "Please enter shared_by."}
                elif not self.is_valid_did(shared_by[0]):
                    return 400, {"status": "error", "error_description": "Please enter valid shared_by."}
                if path[1] == 400:
                    return 400, {"status": "error", "error_description": "Please enter valid path."}
            except Exception as e:
                return 400, {'status': 'error', 'error_description': str(e)+' [#306]'}
            
            return 200, [shared_by[0], path[0]]
            
        except Exception as e:
            return 400, {'status': 'error', 'error_description': str(e)+' [#109]'}
    

    def list_folder(self, request):
        shared_id = request.values.get('shared_id') #do not filter path as it may contain spcl chars.
        if not shared_id:
            return {"status": "error", "error_description": "Please provide shared ID."}, 400
        shared_with = request.values.get('shared_with')
        if not shared_with:
            return {"status": "error", "error_description": "Please provide shared with."}, 400
        path = request.values.get('path')
        return [shared_id, shared_with, path], 200
    

    def read(self, request):
        shared_id = request.values.get('shared_id') #do not filter path as it may contain spcl chars.
        if not shared_id:
            return {"status": "error", "error_description": "Please provide shared id."}, 400
        shared_with = request.values.get('shared_with')
        if not shared_with:
            return {"status": "error", "error_description": "Please provide shared with."}, 400
        path = request.values.get('path')
        return [shared_id, shared_with, path], 200
    

    def download(self, request):
        shared_id = request.values.get('shared_id') #do not filter path as it may contain spcl chars.
        path = request.values.get('path')
        if not shared_id:
            return {"status": "error", "error_description": "Please provide shared id."}, 400
        return "?id="+base64.b64encode(json.dumps({
            'shared_id': shared_id,
            'path': path,
            'token':'token',
            'did':'did'
        })).decode(), 200


    def org_drive_api(self, endpoint="/", request_type="POST", headers=None, data=None):
        client_id = CONFIG['org_drive_api']['client_id']
        ts = str(int(time.time()))
        plain_text_key_created = CONFIG['org_drive_api']['client_secret'] + client_id + ts
        hmac = hashlib.sha3_256(plain_text_key_created.encode()).hexdigest()
        h = {
            "Content-Type": "application/x-www-form-urlencoded",
            "clientid": client_id,
            "hmac": hmac,
            "ts": ts
        }
        if headers: h.update(headers)
        try:
            response = requests.request(request_type, CONFIG['org_drive_api']['url'] + endpoint, data=data, headers=h)
            try:
                return json.loads(response.text), response.status_code
            except Exception:
                return {'status': 'error', 'error_description': 'Failed to connect to server.', 'response': response.text, 'code': response.status_code}, 400
        except Exception as e:
            return {'status': 'error', 'error_description': 'Failed to process your request at the moment.', 'response': str(e)}, 400
    
    def getAccessToken(payload_id):
        post_data = {
            'payload_id': payload_id
        }
        headers = {
            'clientid': CONFIG["adv"]["ADV_API_CID"]
        }
        end_point = CONFIG["adv"]["ADV_API_URL"] +"gettoken"
        response = requests.post(end_point , data=post_data, headers=headers)
        
        return response.text    
    
    def validate_hmac_partners(self, clientid, ts, orgid, digilockerid, hmac):
        if not clientid:
            return {STATUS: ERROR, ERROR_DES: "Invalid clientid"}, 400
        if not ts:
            return {STATUS: ERROR, ERROR_DES: "Invalid ts"}, 400
        if not hmac:
            return {STATUS: ERROR, ERROR_DES: "Invalid hmac"}, 400
        if not orgid:
            return {STATUS: ERROR, ERROR_DES: "Invalid orgid"}, 400
        if not digilockerid:
            return {STATUS: ERROR, ERROR_DES: "Invalid digilockerid"}, 400
        secret = self.get_secret(clientid)
        if not secret:
            return {STATUS: ERROR, ERROR_DES: "Client is not registered"}, 400
        salt = secret+clientid+ts+orgid+digilockerid
        generated_hmac = hashlib.sha3_256(salt.encode()).hexdigest()
        if generated_hmac == hmac:
            return generated_hmac, 200
        else:
            return False, 401
        