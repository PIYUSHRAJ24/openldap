from thefuzz import fuzz, process
from flask import request, Blueprint, g
from lib.drivejwt import DriveJwt
from lib.secretsmanager import SecretManager
from lib.validations import Validations
from lib.constants import *
import datetime
VALIDATIONS = Validations()
bp = Blueprint('name_match', __name__)

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

@bp.before_request
def validate_user():
    """
        Jwt Authentication
    """
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
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
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#12600]"}, 401


@bp.route('/v1', methods=['POST'])
def v1():
    try:
        res, status_code = VALIDATIONS.verify_name(request)
        if status_code == 400:
            return res, status_code
        name = res['name']
        original_name = res['original_name']

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
            return {STATUS: ERROR, "match": match}, 200
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "v1: " + Errors.error('err_1201')+"[#12601]"}, 401

@bp.route('/v2', methods=['POST'])
def v2():
    try:
        res, status_code = VALIDATIONS.verify_name(request)
        if status_code == 400:
            return res, status_code
        name = res['name']
        original_name = res['original_name']
        
        res = process.extract(name, [original_name])
        return {STATUS: SUCCESS, "match": res}, 200
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "v2: " + Errors.error('err_1201')+"[#12602]"}, 401

def name_match_v3(name, original_name):
    try:
        res, status_code = VALIDATIONS.verify_name_v3(name, original_name)
        if status_code == 400:
            return res
        
        name = res['name']
        original_name = res['original_name']
        
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
            return {STATUS: SUCCESS, "match": match}
        else:
            return {STATUS: ERROR, "match": match}

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: "v2: " + Errors.error('err_1201')+"[#12603]"}