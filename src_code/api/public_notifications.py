from flask import request, Blueprint, g
from lib.constants import *
from lib.commonlib import CommonLib
from lib.mongolib import MongoLib
from lib.drivejwt import DriveJwt
from lib.validations import Validations
from lib.rabbitmq import RabbitMQ
from lib.secretsmanager import SecretManager

VALIDATIONS = Validations()
COMMONLIB = CommonLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()

bp = Blueprint('public_notifications', __name__)
notifications_collection_public = CONFIG['notifications']['collection_public']
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

@bp.before_request
def validate():
    """
        Jwt Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {STATUS: ERROR, ERROR_DES: "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls:
            return

        jwtlib = DriveJwt(request, CONFIG)

        jwtres, status_code = jwtlib.jwt_login()

        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
        else:
            return jwtres, status_code

        res, status_code = VALIDATIONS.public_notifications(request)

        if status_code == 400:
            return res, status_code

        g.notification_id = res['notification_id']
        g.digilockerid = res['digilockerid']
        g.message_id = res['message_id']
        g.date_published = res['date_published']
        g.action_taken = res['action_taken']
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT):"+str(e)}, 401

@bp.route('/get', methods=['GET'])
def get_notification():
    query = {}
    if g.notification_id != None:
        query["notification_id"] = g.notification_id
    if g.digilockerid != None:
        query["digilockerid"] = g.digilockerid
    if g.message_id != None:
        query["message_id"] = g.message_id
    if g.date_published != None:
        query["date_published"] = g.date_published
    if g.action_taken != None:
        query["action_taken"] = g.action_taken
    projection = {}
    return MONGOLIB.accounts_eve(notifications_collection_public, query, projection)

@bp.route('/add', methods=['POST'])
def add_notification():
    try:
        res, status_code = VALIDATIONS.public_notifications_model(request, 'C')
        if status_code != 200:
            return res, status_code
        data = res['data']
        return RABBITMQ.dl_notification_mongo(notifications_collection_public, 'C', {"data": data})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: "add_notification: " + str(e)}, 400

@bp.route('/update', methods=['POST'])
def update_notification():
    try:
        res, status_code = VALIDATIONS.public_notifications_model(request, 'U')
        if status_code != 200:
            return res, status_code
        data = res['data']
        return RABBITMQ.dl_notification_mongo(notifications_collection_public, 'U', {"data": data})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: "update_notification: " + str(e)}, 400
