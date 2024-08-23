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
        did = request.values.get('did')
        orgid = request.values.get('orgid')
        digilockerid = request.values.get('digilockerid')
        source = request.values.get('source')
        jwtlib = DriveJwt(request, CONFIG)
        jwtres, status_code = jwtlib.jwt_generate(digilockerid, did, orgid, source)
        return jwtres, status_code
    except Exception as e:
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
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400   
    