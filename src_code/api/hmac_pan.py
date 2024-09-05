from datetime import datetime
import hashlib
import time
import requests
import json
from lib.validations import Validations
from lib.rabbitmqlogs import RabbitMQLogs
from lib.constants import *
from flask import request, Blueprint
from lib.redislib import RedisLib
from lib.mongolib import MongoLib

MONGOLIB = MongoLib()
VALIDATIONS = Validations()
RABBITMQ = RabbitMQLogs()
REDISLIB = RedisLib()

CURLTIMEOUT = 8
bp = Blueprint('hmac_pan', __name__)
logarray = {}


@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    logarray.update({
        ENDPOINT: request.path,
        HEADER: {
            'user-agent': request.headers.get('User-Agent'),
            "client_id": request.headers.get("client_id"),
            "ts": request.headers.get("ts"),
            "hmac": request.headers.get("hmac")
        },
        REQUEST: {}
    })
    if dict(request.args):
        logarray[REQUEST].update(dict(request.args))
    if dict(request.values):
        logarray[REQUEST].update(dict(request.values))
    if request.headers.get('Content-Type') == "application/json":
        logarray[REQUEST].update(dict(request.json)) # type: ignore
    
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls:
            return

        res, status_code = VALIDATIONS.hmac_authentication_sha3(request)

        if status_code != 200:
            return res, status_code

    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 401


@bp.route('/verify_pan', methods=['POST'])
def verify_pan():
    try:
        res, status_code = VALIDATIONS.verify_pan(request, True)
        if status_code != 200:
            logarray.update(res)
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return res, status_code
        txn_id = res['txn_id']
        pan = res['post_data']['orgPan']
        url = CONFIG['pan']['pan_url']
        headers = {
            'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
            'X-APISETU-CLIENTID': CONFIG['mca']['client_id'],
            'Content-Type': 'application/json'
        }
        try:
            response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']), timeout=CURLTIMEOUT)
        except requests.exceptions.ReadTimeout:
            try:
                response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']), timeout=CURLTIMEOUT)
            except requests.exceptions.ReadTimeout:
                try:
                    response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']), timeout=CURLTIMEOUT)
                except requests.exceptions.ReadTimeout:
                    logarray.update({RESPONSE: {STATUS: ERROR, RESPONSE: Errors.error("ERR_MSG_164")+" - apisetu read timed out"}})
                    RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_164")}, 400
        if response.status_code >= 500 and response.status_code < 600:
            logarray.update({RESPONSE: response.text})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164'), RESPONSE: response.text}, 400
        elif not (response.status_code >= 200 and response.status_code < 300):
            try:
                res = json.loads(response.text)
            except Exception:
                response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']), timeout=CURLTIMEOUT)
                try:
                    res = json.loads(response.text)
                except Exception:
                    logarray.update({ERROR_DES: Errors.error('ERR_MSG_164'), RESPONSE: response.text})
                    RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_184'), RESPONSE: response.text}, 400
            logarray.update({RESPONSE: res})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            if res.get("verificationResult") and res["verificationResult"].get("orgName") != "Y":
                return { STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_125')}, 400
            if res.get("verificationResult") and res["verificationResult"].get("doi") != "Y":
                return { STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_152')}, 400
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_134'), RESPONSE: res.get('errorDescription') or res}, response.status_code
        if not save_uri(txn_id, pan):
            return { STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_207')}, 400
        return {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_100'), 'txn': txn_id}, 200
    except Exception as t:
        logarray.update({RESPONSE: str(t)})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_184'), RESPONSE: str(t)}, 400

        

def save_uri(txn_id, pan):
    ts = int(time.time())
    ci = '0000'
    key = f"{txn_id}{ci}{ts}"
    hmac = hashlib.sha256(key.encode()).hexdigest()

    headers = {
        'ts': str(ts),
        'lockerRequestToken': hmac,
        'uid': txn_id,
        'Content-Type': 'application/json'
    }

    data = {
        "userName": txn_id,
        "uri": f"in.gov.pan-OPNCR-{pan}",
        "orgId": "001891",
        "orgName": "Income Tax Department",
        "docIssueType": "Public",
        "docTypeId": "OPNCR",
        "issuerId": "in.gov.pan",
        "docName": "PAN Verification Record",
        "docId": pan,
        "issuedOn": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "createdBy": txn_id,
        "modifiedBy": txn_id,
        "recordFrom": "MSTL",
        "digilockerId": txn_id
        }
    ids_api_url = CONFIG["ids"]["url"]
    url = f"{ids_api_url}api/2.0/save-uri"
    response = requests.post(url, headers=headers, json=data)
    return response.status_code == 200


@bp.route('/verify_icai', methods=['POST'])
def verify_icai():
    res, status_code = VALIDATIONS.verify_icai(request)
    if status_code != 200:
        return res, status_code
    url = CONFIG['pan']['icai_url']
    headers = {
        'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
        'X-APISETU-CLIENTID': CONFIG['mca']['client_id'],
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']))
    if response.status_code >= 500 and response.status_code < 600:
        logarray.update({ERROR_DES: Errors.error('ERR_MSG_164'), RESPONSE: response.text})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164'), RESPONSE: response.text}, response.status_code
    elif not (response.status_code >= 200 and response.status_code < 300):
        try:
            res = json.loads(response.text)
        except Exception:
            logarray.update({RESPONSE: response.text})
            RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: response.text}, 400
        logarray.update({RESPONSE: res})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: res.get('errorDescription') or Errors.error('ERR_MSG_111'), RESPONSE: res.get('error') or res}, response.status_code
    return {STATUS: SUCCESS, MESSAGE: Messages.message('MSG_101')}, 200
