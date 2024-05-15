import hashlib
import json
import requests
from datetime import datetime,timedelta 
from flask import Blueprint, request, g
from lib.commonlib import CommonLib
from lib.profile_model import ProfileModel
from lib.constants import *
from lib.secretsmanager import SecretManager
import urllib.parse
import uuid
from api.accounts_profile import v1_without_auth
import secrets
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
import string
import secrets
from lib.redislib import RedisLib
rs = RedisLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
CONFIG = {}
token_time = os.getenv('TOKEN_TIME')
secrets_v = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets_v.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

CommonLib = CommonLib(CONFIG)
bp = Blueprint('shared_profile_token', __name__)

@bp.before_request
def before_request():
    try:
        request_data = request.values
        g.logs = {'post_data': dict(request_data), 'req_header': {**request.headers}}

    except Exception as e:
        log_data = {'status':'error', 'actual_error':str(e), 'step':'before_req'}
        print(str(e))


@bp.route('/generate', methods=['POST'])
def get_token():
    try:
        res, status_code = CommonLib.validate_token(request)
        if status_code == 200:
            user = res[0]
        else:
            return res, status_code
        
        res, code = MONGOLIB.accounts_eve_v2('shared_profile_token', {"digilockerid": user}, {})
        
        if code == 200 and res['status'] == 'success' and res.get('response') is not None:
            token_data = res['response'][0]  # Token data if found
            created_time_str = token_data.get('created_on')
            
            if created_time_str:
                created_time = datetime.fromisoformat(created_time_str)
                time_difference = datetime.now() - created_time
                if time_difference > timedelta(minutes=int(token_time)):
                    # Token has expired, generate a new token
                    token = generate_token()
                    store_data = {
                        "created_on": datetime.now().isoformat(),
                        "digilockerid": user,
                        "token": token
                    }
                    res, status_code = RABBITMQ.send_to_queue({"data": store_data }, 'Shared_profile_token_Xchange', 'Shared_profile_token_')
                    if status_code != 200:
                        return {'status': 'error', 'error_description': 'Some technical error'}, 400
                    
                    data = {
                        'status': 'success',
                        'token': token
                    }
                else:
                    # Token is still valid, return it
                    data = {
                        'status': 'success',
                        'token': token_data.get('token')
                    }
            else:
                # No created time found, generate a new token
                token = generate_token()
                store_data = {
                    "created_on": datetime.now().isoformat(),
                    "digilockerid": user,
                    "token": token
                }
                res, status_code = RABBITMQ.send_to_queue({"data": store_data }, 'Shared_profile_token_Xchange', 'Shared_profile_token_')
                if status_code != 200:
                    return {'status': 'error', 'error_description': 'Some technical error'}, 400
                
                data = {
                    'status': 'success',
                    'token': token
                }
        else:
            # If digilocker ID not found, generate a new token
            token = generate_token()
            store_data = {
                "created_on": datetime.now().isoformat(),
                "digilockerid": user,
                "token": token
            }
            res, status_code = RABBITMQ.send_to_queue({"data": store_data }, 'Shared_profile_token_Xchange', 'Shared_profile_token_')
            if status_code != 200:
                return {'status': 'error', 'error_description': 'Some technical error'}, 400
            
            data = {
                'status': 'success',
                'token': token
            }
                
        return data, status_code
        
    except Exception as e:
        return {'status': 'error', 'error_description': str(e)}, 400


@bp.route('/shared_profile', methods=['POST'])
def check_token():
    res_data ={}
    token = request.values.get('token')
    if token is None:
        return {'status':'error','error_description':'token is empty or invalid=> Invalid token.'},400
    res, code = MONGOLIB.accounts_eve_v2('shared_profile_token', {"token": token}, {})
   
    if code == 200 and res['status'] == 'success' and res.get('response') is not None:
        digilockerid = res['response'][0].get('digilockerid')
        created_time = res['response'][0].get('created_on')
        created_time = datetime.fromisoformat(created_time)
        time_difference = datetime.now() - created_time
        if time_difference > timedelta(minutes= int(token_time)):
            return {'status': 'error', 'error_description': 'This token has been expired or invalid.'}, 400

        if digilockerid is not None:
            profile_data,code = v1_without_auth(digilockerid)
            res_data['name'] = profile_data.get('full_name', None)
            res_data['gender'] = profile_data.get('gender', None)
            res_data['mobile'] = profile_data.get('mobile', None)
            res_data['email'] = profile_data.get('email', None)
            res_data['photo'] = profile_data.get('photo', None)
            return res_data,code
        
    return {'status':'error','error_description':'Profile not found.'},404 
   

def generate_token(length=10):
    alphabet_size = len(string.ascii_letters + string.digits)
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

