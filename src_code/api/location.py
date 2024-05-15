from flask import request, Blueprint
from lib.redislib import RedisLib
from lib.commonlib import CommonLib
from lib.rabbitmq import RabbitMQ
from lib.validations import Validations
from lib.elasticlib import ElasticLib
from lib.constants import *
from geopy.geocoders import Nominatim
from datetime import datetime
import datetime

geolocator = Nominatim(user_agent='user-location')

VALIDATIONS = Validations()
COMMONLIB = CommonLib()
REDISLIB = RedisLib()
RABBITMQ = RabbitMQ()
ELASTICLIB = ElasticLib()
bp = Blueprint('location', __name__)
logarray ={}
@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        
        res, status_code = COMMONLIB.validation_rules_v1(request)
        if status_code != 200:
            return res, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400

@bp.route('/save_location',methods =['POST'])
def save_location():
    try:
        res, status_code = VALIDATIONS.user_location(request)
        if status_code == 200:
            browser_name,lat,lon, lockerid,public_ip, server_ip,  = res
        else:
            return res, status_code
        try:
            location = geolocator.reverse(f"{lat}, {lon}")
            address = location.address
            # Check if location is not found
            if not address:
                return {STATUS: ERROR,ERROR_DES:"Failed to retrieve location."}, 400
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400  
        login_time = datetime.datetime.now()
        data = {
            'lockerid': lockerid,
            'login_history': {
                'browser': browser_name,
                'latitude': lat,
                'longitude': lon,
                'address': address,
                'public_ip': public_ip,
                'server_ip': server_ip,
                'ts': login_time.isoformat()
            }
        }
        logarray.update({"user_history": data,"status":'success'})
        res, code = RABBITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'user_signin_location_')
        return res, code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111')}, 400
    