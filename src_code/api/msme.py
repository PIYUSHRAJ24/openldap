import requests
import json
from datetime import datetime
from lib.validations import Validations
from lib.rabbitmqlogs import RabbitMQLogs
from lib.constants import *
from flask import render_template, request, Blueprint, g
import xml.etree.ElementTree as ET
from lib.redislib import RedisLib

VALIDATIONS = Validations()
RABBITMQ = RabbitMQLogs()
REDISLIB = RedisLib()

bp = Blueprint('msme', __name__)
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
    g.org_id = request.headers.get("orgid")
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

        res, status_code = VALIDATIONS.hmac_authentication(request)

        if status_code != 200:
            return res, status_code

    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 401


@bp.route('/get_udcer', methods=['POST'])
def din():
    res, status_code = VALIDATIONS.get_udcer(request, g.org_id)
    if status_code != 200:
        return res, status_code
    mobile = res['post_data']['consentArtifact']['consent']['user']['mobile']
    if not REDISLIB.get(mobile+"_verified_udyam_otp"):
        logarray.update({STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_173'), RESPONSE: mobile})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return render_template('pages/force_access.html')

    url = CONFIG['msme']['udcer_url']
    headers = {
        'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
        'X-APISETU-CLIENTID': CONFIG['mca']['client_id'],
        'accept': 'application/xml',
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']))
    if response.status_code >= 500 and response.status_code < 600:
        logarray.update({RESPONSE: response.content})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_164'), RESPONSE: response.content}, response.status_code
    elif response.status_code >= 200 and response.status_code < 300:
        response_xml = ET.fromstring(response.content)
        data = {}
        enterprise = './/Enterprise'
        doi = response_xml.find('.//UdyamRegistrationCertificate').get('dateOfIncorporation') or ''# type: ignore
        try:
            doi = datetime.strptime(doi, "%d-%m-%Y")
            doi = doi.strftime(D_FORMAT)
        except Exception:
            doi = None
        data['enterprise_name'] = response_xml.find('.//Unit1').get('name') # type: ignore
        data['phone'] = response_xml.find(enterprise).get('phone') # type: ignore
        data['email'] = response_xml.find(enterprise).get('email') # type: ignore
        data['date_of_incorporation'] = doi
        logarray.update({RESPONSE: data})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: SUCCESS, RESPONSE: data}, 200
    else:
        res = json.loads(response.content)
        logarray.update({RESPONSE: res})
        RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: res.get('errorDescription') or Errors.error('ERR_MSG_111'), RESPONSE: res.get('error') or res}, response.status_code