from datetime import datetime
import hashlib
import json
import requests
from flask import Blueprint, request, g
from lib.constants import *
from lib.redislib import RedisLib
from lib.commonlib import CommonLib
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

REDISLIB = RedisLib()
COMMONLIB = CommonLib()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
bp = Blueprint('uid_services', __name__)


@bp.before_request
def default():
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck', 'sha3_256')
        g.endpoint = request.endpoint.split('.')[-1]
        if g.endpoint in bypass_urls or g.endpoint in bypass_urls:
            return
        res, code = COMMONLIB.validate_hmac(g.endpoint)
        g.clientid = COMMONLIB.clientid
        if code != 200:
            return res, code
        g.data = res['data']
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_401'), RESPONSE: "JWT: " + str(e)}, 401


@bp.route('/healthcheck', methods=['GET'])
def healthcheck():
    return {STATUS: SUCCESS}

@bp.route('/sha3_256')
def sha3_256():
    plaintext = request.json.get('plaintext')
    if plaintext:
        return {'hash': hashlib.sha3_256(request.json.get('plaintext').encode()).hexdigest(), 'msg': 'Hash Generated.'}
    else:
        return {'hash': None, 'msg': 'Please provide plaintext.'}, 400


@bp.route('/demoauth', methods=['POST'])
def demoauth():
    try:        
        txn =  g.data['uid'] + datetime.now().strftime("%Y%m%d%H%M%S") + "DGLKR" 
        access_token = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' 
        payload = 'uid='+g.data['uid']+'&fullname='+g.data['name']+'&gender='+g.data['gender']+'&dob='+g.data['dob']+'&pin='+''+'&aadhaar_token='+access_token+'&transaction_id='+txn+'&consent='+g.data['consent']            
        curl_response = requests.request("POST", CONFIG["uidailib"]["uidai_demo_auth_api_url"], headers=HEADERS, data=payload, timeout=30)
        try:
            res = json.loads(curl_response.text)
        except Exception as e:
            return {"status": "error", "error_description": "Our server could not verify your identity at the moment. Please try again after sometime. If the issue still persists kindly contact support at https://www.digilocker.gov.in/about/contact-us", 'response': str(e)}, 400
        return res, curl_response.status_code
    except Exception as e:
        return {"status": "error", "error_description": Errors.error('ERR_MSG_111'),'response': "demoauth:" +str(e)}, 400

@bp.after_request
def after_request(response):
    status = False
    if response.content_type == 'application/json':
        data = response.get_json()
        status = True if data.get('status') in (True, "true", "success") else False
    log_data = {
            'flow': 'demoauth',
            'api_name': 'acsapi',
            'otp_type': 'UIDAI',
            'client_id': g.clientid,
            'code': response.status_code,
            'status': status
        }
    RABBITMQ_LOGSTASH.log_adh_requests(log_data, 'adh_demo_'+APP_ENVIRONMENT)
    return response