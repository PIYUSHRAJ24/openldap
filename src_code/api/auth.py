import datetime
import hashlib
import random
import uuid
from flask import request, Blueprint, g, render_template, jsonify
import requests
import os
import time
from lib.constants import *
from lib.validations import Validations
from lib.elasticlib import ElasticLib
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from lib.connectors3 import Connectors3
from api.org_activity  import activity_insert
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.aadhaarServices import AADHAAR_services
from api.name_match import name_match_v3
from assets.images import default_avatars
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

ELASTICLIB = ElasticLib()
VALIDATIONS = Validations()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
REDISLIB = RedisLib()
CONNECTORS3 = Connectors3()
AADHAAR_CONNECTOR = AADHAAR_services(CONFIG)
from lib import otp_service
otp_connector = otp_service.OTP_services()
logs_queue = 'org_logs_PROD'
bp = Blueprint('auth', __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET')

@bp.route('/getjwt', methods=['POST'])
def getjwt(post_data = None):
    try:        
        #hmac = secret+clientid+ts+clientid+orgid+digilockerid
        did = request.values.get('did') or ""
        orgid = request.values.get('orgid')
        ts = request.values.get('ts')
        hmac = request.values.get('hmac')
        clientid = request.values.get('clientid')
        digilockerid = request.values.get('digilockerid')
        source = request.values.get('source') or "web"
        _, status_code = CommonLib().validate_hmac_partners(clientid,ts,clientid,orgid,digilockerid,hmac)
        if status_code != 200:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_122')}, 401
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_generate(digilockerid, did, orgid, source)
        return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/refreshjwt', methods=['POST'])
def refreshjwt(post_data = None):
    try:
        did = request.values.get('did')
        orgid = request.values.get('orgid')
        digilockerid = request.values.get('digilockerid')
        refresh_token = request.values.get('refresh-token')
        source = request.values.get('source')
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.refresh_jwt(refresh_token, digilockerid, did, orgid, source)
        return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400   


@bp.route('/token', methods=['POST'])
def token(post_data = None):
    try:        
        #hmac = secret+clientid+ts+clientid+orgid+digilockerid
        did = request.headers.get('device-security-id') or ""
        orgid = request.headers.get('orgid')
        ts = request.headers.get('ts')
        hmac = request.headers.get('hmac')
        clientid = request.headers.get('clientid')
        digilockerid = request.headers.get('user')
        source = request.headers.get('source') or "web"
        _, status_code = CommonLib().validate_hmac_partners_256(clientid,ts,clientid,orgid,digilockerid,hmac)
        if status_code != 200:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_122')}, 401
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_generate(digilockerid, did, orgid, source)
        return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/refresh', methods=['POST'])
def refresh(post_data = None):
    try:
        did = request.headers.get('device-security-id') or ""
        orgid = request.headers.get('orgid')
        refresh_token = request.headers.get('refresh-token')
        digilockerid = request.headers.get('user')
        source = request.headers.get('source') or "web"
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.refresh_jwt(refresh_token, digilockerid, did, orgid, source)
        return jwtres, status_code
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400   
    