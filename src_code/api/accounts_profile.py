import hashlib
import json
import requests
import xmltodict
from datetime import datetime
from flask import Blueprint, request, g
from lib.commonlib import CommonLib
from lib.profile_model import ProfileModel
from lib.constants import *
from lib.secretsmanager import SecretManager
from php import Php
import time
import urllib.parse
from lib.rabbitmq import RabbitMQ
from lib.rabbitMQAcsUsers import RabbitMQAcsUsers
acs_rmq = RabbitMQ()
users_acs_rmq = RabbitMQAcsUsers()

CONFIG = {}
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

CommonLib = CommonLib(CONFIG)
ProfileModel = ProfileModel()

from lib.mongolib import MongoLib

MONGOLIB = MongoLib()

from lib.redislib import RedisLib

rs = RedisLib()

from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

rmq = RabbitMQTaskClientLogstash()

from lib import otp_service 
otp_connector = otp_service.OTP_services()

bp = Blueprint('accounts_profile', __name__)

rmq_queue = 'ACS_api_logs_users_profile'

USERDATA = '_user_data_cluster_misc'  # get from configinit
USERS = '_users_cluster_misc'  # get from configinit

@bp.before_request
def before_request():
    try:
        request_data = request.values
        g.logs = {'post_data': dict(request_data), 'req_header': {**request.headers}}
        
        g.address = request.values.get('address')
        if g.address is not None and g.address not in ['yes', 'no']:
            return {STATUS: ERROR, ERROR_DES: 'invalid input for aadress field given.'}, 400
        else:
            g.address = True if g.address == 'yes' else False
        g.dl = request.values.get('dl')
        if g.dl is not None and g.dl not in ['yes', 'no']:
            return {STATUS: ERROR, ERROR_DES: 'invalid input for dl field given.'}, 400
        else:
            g.dl = True if g.dl == 'yes' else False
        g.pan = request.values.get('pan')
        if g.pan is not None and g.pan not in ['yes', 'no']:
            return {STATUS: ERROR, ERROR_DES: 'invalid input for pan field given.'}, 400
        else:
            g.pan = True if g.pan == 'yes' else False
        g.masked_aadhaar = request.values.get('masked_aadhaar')
        if g.masked_aadhaar is not None and g.masked_aadhaar not in ['yes', 'no']:
            return {STATUS: ERROR, ERROR_DES: 'invalid input for masked_aadhaar field given.'}, 400
        else:
            g.masked_aadhaar = True if g.masked_aadhaar == 'yes' else False
        g.resident_photo = request.values.get('resident_photo')
        if g.resident_photo is not None and g.resident_photo not in ['yes', 'no']:
            return {STATUS: ERROR, ERROR_DES: 'invalid input for resident_photo field given.'}, 400
        else:
            g.resident_photo = True if g.resident_photo == 'yes' else False

    except Exception as e:
        log_data = {'status':'error', 'actual_error':str(e), 'step':'before_req'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        print(str(e))


@bp.route('/get_lockerid', methods=['POST'])
def return_lockerid():
    try:
        res, status_code = CommonLib.validation_rules(request)
           
        if status_code == 200:
            user = res[0]
        else:
            return res, status_code

        users_data = get_user_lockerid(user)
        return users_data
    
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111")}

        return res, 400
    
def get_user_lockerid(user):
    try:  
        if len(user) != 12:
            return {'status': 'error', 'error_description': 'rewrite aadhar number'}, 400
        uid = hashlib.md5(user.encode('utf-8')).hexdigest()

        res, code = MONGOLIB.accounts_eve_v2('users', {"uid":uid}, {})
        if code == 200 and res.get('status') == 'success' and res.get('response') is not None:
            data = res['response']
            if len(data)>1:
                return {'status':'error', 'error_description':'Multiple records found'}, 400
            
            return {'status':'success', "digilockerid":data[0].get('digilockerid')}
        else:
            return {'status':'error', 'error_description':'users profile data not found'}, 400
    except Exception as e:
        return {'status':'error', 'error_description':str(e)}, 400
    
@bp.route('/1.0', methods=['POST'])
def v1(auth_mode = 'HMAC', uid_remove = None):
    try:
        g.logs['requested_mode'] = auth_mode
        g.uid_remove = uid_remove
        if auth_mode == 'HMAC':
            res, status_code = CommonLib.validation_rules(request)
        else:
            res, status_code = CommonLib.validate_token(request)
           
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            log_data = res
            log_data['step'] = 'validation_err'
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            res.pop('step', None)
            res.pop('err', None)
            return res, status_code

        users_data = get_users(user)
        user = users_data.get("digilockerid") if users_data.get("digilockerid") else user # this to be used further
        if len(users_data) == 0:
            return {'status': 'error', 'error_description': 'Data not found.'}, 400

        
        users_data['isAadhaarSeeded'] = 'Y' if users_data.get('user_type') in ['aadhaar', 'trusted_partners'] else 'N'
        users_data['email_id_verified'] = 'Y' if users_data.get('email_id_verified') == 1 else 'N'
        users_data['isAccountVerified'] = 'Y' if users_data.get('user_type') in ['aadhaar','trusted_partners','non_aadhaar'] else 'N'
        uid_token = users_data.get('uid_token')

        uid_token_hash = None
        if uid_token:
            uid_token_hash = hashlib.md5(uid_token.encode('utf-8')).hexdigest()
        
        if uid_token and users_data.get('user_type') == 'aadhaar' and not users_data.get('uid'):
            kyc_data = getKycData(users_data.get('digilockerid'), uid_token, True)
            aadhaarNum = kyc_data.get('aadhaarNumber')
            if aadhaarNum and len(aadhaarNum) == 12:
                users_data['uid'] = hashlib.md5(aadhaarNum.encode('utf-8')).hexdigest()

        ekyc_data = {}
        ekyc_found = False
        if uid_token_hash:
            ekyc = getKYCDataFromAPI(uid_token_hash, user)
            ekyc_found = True if len(ekyc) >0 else False
            ekyc_data['careOf'] = ekyc.get('careOf') if ekyc.get('careOf') else ''
            ekyc_data['pincode'] = ekyc.get('pincode') if ekyc.get('pincode') else ''
            ekyc_data['postOffice'] = ekyc.get('postOffice') if ekyc.get('postOffice') else ''
            ekyc_data['phone'] = ekyc.get('phone') if ekyc.get('phone') else ''
            ekyc_data['houseNumber'] = ekyc.get('houseNumber') if ekyc.get('houseNumber') else ''
            ekyc_data['street'] = ekyc.get('street') if ekyc.get('street') else ''
            ekyc_data['photo'] = ekyc.get('photo') if ekyc.get('photo') else ''
            ekyc_data['maskedAadhaar'] = ekyc.get('maskedAadhaar') if ekyc.get('maskedAadhaar') else ''
            ekyc_data['landmark'] = ekyc.get('landmark') if ekyc.get('landmark') else ''
            ekyc_data['locality'] = ekyc.get('locality') if ekyc.get('locality') else ''
            ekyc_data['subDistrict'] = ekyc.get('subDistrict') if ekyc.get('subDistrict') else ''
            ekyc_data['district'] = ekyc.get('district') if ekyc.get('district') else ''
            ekyc_data['state'] = ekyc.get('state') if ekyc.get('state') else ''
            ekyc_data['name'] = ekyc.get('residentName') if ekyc.get('residentName') else ''
            ekyc_data['date_of_birth'] = format_dob(ekyc.get('dateOfBirth')) if ekyc.get('dateOfBirth') else ''
            ekyc_data['gender'] = ekyc.get('gender') if ekyc.get('gender') else ''
        
        if users_data['user_type'] == 'aadhaar' and ekyc_found:
            users_p_data = ekyc_data
        elif users_data['user_type'] == 'aadhaar':
            users_p_data = get_usersProfile(user)
            users_p_data['date_of_birth'] = format_dob(users_p_data.get('date_of_birth'))
            ekyc_data = users_p_data
        else:
            users_p_data = get_usersProfile(user)
            users_p_data['date_of_birth'] = formate_dob_non_aadhaar(users_p_data.get('date_of_birth'))
        
        users_ext_data = getAccountExtentionDataByLockerid(user)
        xml_modified_on = users_data.get('xml_modified_on')
        digilockerid = users_data.get('digilockerid')
        if users_data.get('user_type') == 'aadhaar' and not xml_modified_on:
            updateStatus = update_xml_modified_on(digilockerid)
            if updateStatus.get('status') and updateStatus.get('LastModified') != None:
                userUpdateData = {}
                userUpdateData['digilockerid'] = digilockerid
                userUpdateData['xml_modified_on'] = formate_last_modified(updateStatus.get('LastModified'))
                users_acs_rmq.updateUser(userUpdateData)
                users_data['xml_modified_on'] = updateStatus.get('LastModified')      
        final_data = formatting(users_data, users_p_data, ekyc_data, users_ext_data)

        if type(final_data) == type({}) and final_data is not None:
            log_data = {'api_response': final_data, 'step':'served', 'status':'success'}
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return final_data, 200
        else:
            res = {'status': 'error', 'error_description': 'Data not found.'}
            log_data = res
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return res, 400
            

    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111")}
        log_data = res
        log_data['actual_error'] = str(e)
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return res, 400

@bp.route('/1.1', methods=['POST'])
def v1_1():
    return v1(auth_mode='JTOKEN')

@bp.route('/1.2', methods=['POST'])
def v2_2():
    
    if request.values.get('hmac'):
        return v1(uid_remove ='Y')
    else:
        return v1(auth_mode = 'JTOKEN', uid_remove ='Y')
        

def get_users(user, req_from=None):
    try:
        
        if req_from == 'authenticator':
            g.logs = {}
        from_redis = rs.get(user + USERS)

        if from_redis is not None and len(json.loads(from_redis)) != 0:
            redis_data = json.loads(from_redis)
            if redis_data.get('user_type') == 'aadhaar' and redis_data.get('uid') != None:
                return redis_data
         
        if len(user) == 36:
            where = {"digilockerid": user}
        else:
            where = {"user_id": user}
        
        res, code = MONGOLIB.accounts_eve_v2('users', where, {})
        
        if code == 200 and res.get('status') == 'success' and res.get('response') is not None:
            data = res['response'][0]
            rs.set(user + USERS, json.dumps(data))
            return data
        else:
            # log_data = {'status':'error', 'error_description':'users data not found', 'step':'get_users_coll', 'query':json.dumps(where), 'eve_response':res.get('response')}
            # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return {}
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get users_coll'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}

def update_xml_modified_on(lockerid=None):
    try:
        curlurl = os.getenv('ids_api_url') + "api/1.0/get_xml_modified_on"
        ts= str(int(time.time()))
        secret = os.getenv('ids_client_secret')
        clientid = os.getenv('ids_client_id')
        partner_id = os.getenv('ids_partner_id')
        
        key = secret + clientid + lockerid + ts + partner_id
        hmac = hashlib.sha256(key.encode()).hexdigest()
        headers = {
            'digilockerid' : lockerid,
            'ts' : ts,
            'clientid' : clientid,
            'partner_id' : partner_id,
            'hmac' : hmac
        }
        curl_result = requests.request("POST", curlurl, headers=headers, data={})
        response = json.loads(curl_result.text)
        return response
    
    except Exception as e:
        log_data = {'status':'error', 'error_description':str(e), 'step':'exception_while_get_xml_modified_on'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {"status" : False}
    
def get_usersProfile(user,req_from=None):
    if req_from == 'authenticator':
        g.logs = {}
        
    g.logs['user_to_be_found'] = user
    try:
        res, code = MONGOLIB.accounts_eve_v2('users_profile', {"digilockerid": user}, {})

        if code == 200 and res['status'] == 'success' and res.get('response') is not None:
            return res['response'][0]
        else:
            # log_data = {'status':'error', 'error_description':'users profile data not found', 'step':'get_users_profile_coll'}
            # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return {}
    except Exception as e:
        log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get users_profile_coll'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}

def getKycData(lockerid, uid_token, update=False):
    g.logs['user_to_be_found'] = lockerid
    g.logs['uid_token_to_be_found'] = uid_token
    try:
        url = os.getenv('profile_app_url') + 'UidaiV3/eKYCgetDetails'
        ts= str(int(time.time()))
        client_id = os.getenv('default_clientid')
        p_data = {
            'OTP' :'000000',
            'aadhaarNumber' : urllib.parse.quote(uid_token),
            'ts' : ts,
            'clientid' : client_id,
            'digilockerid':lockerid
        }
        post_data  = Php.http_build_query(p_data)
        
        key = os.getenv('default_secret') + client_id + ts + p_data['aadhaarNumber']+ p_data['OTP'] 
        p_data['hmac'] = hashlib.sha256(key.encode()).hexdigest()
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.request("POST", url, headers=headers, data=post_data)
        pure_data = {}
        if response.status_code == 200:
            res= json.loads(response.text)
            if res.get('status') == 'success' and res.get('data'):
                pure_data = json.loads(CommonLib.aes_decryption(res.get('data').replace('---', '+'), CONFIG.get('JWT_SECRET')))
             
        if update and pure_data.get('aadhaarNumber'):
            profile_data = {}
            user_data = {}
            
            '''sync profile data'''
            if pure_data.get('name'):
                profile_data['name'] = pure_data.get('residentName')
            
            if pure_data.get('gender'):
                profile_data['gender'] = pure_data.get('gender')
            
            if pure_data.get('dateOfBirth'):
                formatted_dob = format_kyc_dob(pure_data.get('dateOfBirth'))
                if formatted_dob:
                    profile_data['date_of_birth'] = formatted_dob
            
            if pure_data.get('vtc'):
                profile_data['city'] = pure_data.get('vtc')
            
            if pure_data.get('state'):
                profile_data['state'] = pure_data.get('state')
            
            if pure_data.get('district'):
                profile_data['district'] = pure_data.get('district')
            
            profile_data['is_kyc'] = 'Y'
            profile_data['digilockerid'] = lockerid
            users_acs_rmq.updateUserProfile(profile_data)
            
            
            '''sync users data'''
            if pure_data.get('UID_Token'):
                user_data['uid_token'] = pure_data.get('UID_Token')
            
            aadhaarNum = pure_data.get('aadhaarNumber', '')
            if aadhaarNum and len(aadhaarNum) == 12:
                user_data['uid'] = hashlib.md5(aadhaarNum.encode('utf-8')).hexdigest()
            # else:
            #     log_data = {'status':'error', 'step':'12 digit aadhaarNum not found while get_kyc data from api-2'}
            #     rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            
            user_data['user_type'] = 'aadhaar'
            user_data['digilockerid'] = lockerid
            users_acs_rmq.updateUser(user_data)
            
        return pure_data
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get_kyc data from api-2'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}
    
def format_kyc_dob(dob):
    try:
        d2 = datetime.strptime(dob,"%Y-%m-%dT%H:%M:%S.%fZ")
        new_format = "%Y-%m-%d"
        new_dob = d2.strftime(new_format) 
        return new_dob #1998-12-22
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e),'dob_paased':dob, 'step':'exception while kyc_dob formatting'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return None
    
def getAccountExtentionDataByLockerid(digilockerid):
    try:
        res, code = MONGOLIB.accounts_eve_v2('users_info_extended', {"digilockerid": digilockerid}, {})

        if code == 200 and res['status'] == 'success' and res.get('response') is not None:
            return res['response'][0]
        else:
            # log_data = {'status':'error', 'error_description':'ac ext data not found', 'step':'get_ac_extension_coll'}
            # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return {}
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get ac_extension_coll'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}
    


def getKYCDataFromAPI(uid_token_hash, user):
    try:
        rs_key = user + '_kyc_data'
        from_redis = rs.get(rs_key)
        if from_redis is not None:
            return json.loads(from_redis)

        url = os.getenv('uidai_get_data_url')
        
        payload = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><PullDocRequest xmlns:ns2=\"http://tempuri.org/\" ver=\"1.0\" ts=\"2022-02-01T09:03:08+05:30\" txn=\"562ae0e699e2521ac4bd55f5ca61e553\" orgId=\"in.gov.uidai\" keyhash=\"990f29d904518604243d7242b789477b2f6b475105e399a11a963235ed74b29d\" metadata=\"Y\" format=\"xml\"><DocDetails><URI>in.gov.uidai-ADHAR-" + uid_token_hash + "</URI><DigiLockerId>sample00-1aa1-11a1-10a0-digilockerid</DigiLockerId></DocDetails></PullDocRequest>"
        headers = {
            'Content-Type': 'application/xml'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        tree = xmltodict.parse(response.text, attr_prefix='')
        if 'ResponseStatus' in tree.get('xml'):
            if tree.get('xml').get('ResponseStatus').get('StatusCode') == '1':
                data = tree.get('xml').get('DocDetails').get('MetadataContent') or {}
                if data.get('residentName') is None:
                    # log_data = {'status':'error', 'error_description':'kyc data not found-resident name', 'step':'get_kyc data from api'}
                    # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
                    return {}
                if data.get('metadata'):
                    data.pop('metadata')
                rs.set(rs_key, json.dumps(data))
                return data
            else:
                return {}
        else:
            # log_data = {'status':'error', 'error_description':'kyc data not found', 'step':'get_kyc data from api'}
            # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return {}

    except Exception as e:
        log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get kyc data'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}


def format_dob(dob):
    try:
        dob = datetime.strptime(dob, "%Y-%m-%d")
        dob=(dob.strftime('%Y-%m-%dT00:00:00.000000Z')) 
        return dob
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e),'dob_paased':dob, 'step':'exception while aadhaar dob formatting'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return dob
    
def formate_dob_non_aadhaar(dob): 
    try:
        dob = datetime.strptime(dob,"%a, %d %b %Y %H:%M:%S GMT")
        dob = (dob.strftime('%Y-%m-%dT00:00:00.000000Z'))
        return dob
    except Exception as e:
        # log_data = {'status':'error', 'error_description':str(e),'dob_paased':dob, 'step':'exception while non_aadhaar dob formatting'}
        # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return dob  

def formate_last_modified(lastmodify):
    try:
        lastmodify = datetime.strptime(lastmodify,"%a, %d %b %Y %H:%M:%S GMT")
        lastmodify = (lastmodify.strftime('%Y-%m-%d'))
        return lastmodify
    except Exception as e:
        return lastmodify
        

'''below function will return schema as output'''


def formatting(userData={}, userProfileData={}, ekycData={}, userExtendedData={}):
    try:
        response_data = {
            # '''users & profile things'''
            
            "lockerid": userData.get('digilockerid') or '',
            "user_id": userData.get('user_id') or '',
            "user_type": userData.get('user_type') or '',
            "user_alias": userData.get('user_alias') or '',
            "uid_token_hash": userData.get('uid_token_hash') or '',
            "mobile": userData.get('mobile_no') or '',
            "isAadhaarSeeded": userData.get('isAadhaarSeeded') or '',
            "UID_Token": userData.get('uid_token') or '',
            "email": userData.get('email_id') or '',
            "email_verified": userData.get('email_id_verified') or '',
            "aadhaar": userData.get('uid') or '',
            "isAccountVerified": userData.get('isAccountVerified') or '',
            "xml_modified_on": userData.get('xml_modified_on') or '',

            "date_of_birth": userProfileData.get('date_of_birth') or '',
            "gender": userProfileData.get('gender') or '',
            "full_name": userProfileData.get('name') or '',
            # '''kyc data'''

            "address": {
                "careOf": ekycData.get('careOf') if g.address and ekycData.get('careOf') else '',
                "district": ekycData.get('district') if g.address and ekycData.get('district') else '',
                "houseNumber": ekycData.get('houseNumber') if g.address and ekycData.get('houseNumber') else '',
                "landmark": ekycData.get('landmark') if g.address and ekycData.get('landmark') else '',
                "locality": ekycData.get('locality') if g.address and ekycData.get('locality') else '',
                "phone": ekycData.get('phone') if g.address and ekycData.get('phone') else '',
                "pincode": ekycData.get('pincode') if g.address and ekycData.get('pincode') else '',
                "postOffice": ekycData.get('postOffice') if g.address and ekycData.get('postOffice') else '',
                "state": ekycData.get('state') if g.address and ekycData.get('state') else '',
                "street": ekycData.get('street') if g.address and ekycData.get('street') else '',
                "subDistrict": ekycData.get('subDistrict') if g.address and ekycData.get('subDistrict') else '',
            },

            "masked_aadhaar": ekycData.get('maskedAadhaar') if g.masked_aadhaar and ekycData.get(
                'maskedAadhaar') else '',
            "resident_photo": ekycData.get('photo') if g.resident_photo and ekycData.get('photo') else '',

            # '''accounts ext things'''

            "pan": userExtendedData.get('PAN') if g.pan and userExtendedData.get('PAN') else '',
            "dl": userExtendedData.get('DL') if g.dl and userExtendedData.get('DL') else '',
            
            # '''account verify by things'''
            "verified_by":  "aadhaar" if userData.get('user_type') == 'aadhaar' else userProfileData.get('converted_by', ''),
            # '''sha 256 of 12 digit aadhaar No '''
            "refkey_sha256":  userExtendedData.get('uid_256', ''),
            #''' face_auth  logic to do be implemented '''
            "is_fa_req" : "Y"  
        }
        if g.uid_remove:
            response_data.pop('aadhaar', None)
        
        return response_data
    except Exception as e:
        log_data = {'status':'error', 'error_description':str(e), 'step':'exception while formatting final data'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}




@bp.route('/send_otp/1.0', methods=['POST'])
def send_otp():
    try:
        g.logs['api_name'] = 'send_otp/1.0'
        log_data = {}
        res, status_code = CommonLib.validate_token(request)  
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            log_data = res
            log_data['step'] = 'validation_err'
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            res.pop('step')
            return res, status_code
        users_data = get_users(user)
        mobile = users_data.get('mobile_no')
        if mobile and len(mobile)==10:
            res, code = otp_connector.send_mobile_otp(mobile)
        else:
            res = {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_129")}
            code = 400
        
        log_data['mobile'] = mobile
        rmq.log_stash_logeer({**res, **g.logs}, rmq_queue)
        return res, code
    except Exception as e:
        log_data = res
        log_data['error'] = str(e)
        log_data = {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_111")}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        res.pop('error')
        return res, 400
    
@bp.route('/verify_otp/1.0', methods=['POST'])
def verify_otp():
    try:
        g.logs['api_name'] = 'verify_otp/1.0'
        res, status_code = CommonLib.validate_token(request)
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            log_data = res
            log_data['step'] = 'validation_err'
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            res.pop('step')
            return res, status_code
        otp = request.values.get('otp')
        if otp is None or len(otp) != 6:
            return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_130")}, 400
        
        users_data = get_users(user)
        mobile = users_data.get('mobile_no')
        if mobile and len(mobile)==10:
            res, code = otp_connector.verify_mobile_otp(mobile,otp)
            return res, code
        else:
            return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_129")}, 400
    except Exception as e:
        log_data = res
        log_data['error'] = str(e)
        log_data = {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_111")}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        res.pop('error')
        return res, 400
    
@bp.route('/xml/1.0', methods=['POST'])
def xml():
    try:
        res, status_code = CommonLib.validate_token(request)
        if status_code == 200:
            user = res[0]
        else:
            log_data = res
            log_data['step'] = 'validation_err'
            rmq.log_stash_logeer({**log_data, **g.logs}, 'acs_xml_api_logs')
            res.pop('step', None)
            res.pop('err', None)
            return res, status_code
        g.logs['digilockerid'] = user
        users_data = get_users(user)
        user = users_data.get("digilockerid")
        uid_token = users_data.get('uid_token')
        if len(users_data) == 0 or uid_token is None:
            res = {'status': 'error', 'error_description': 'Data not found.'}
            rmq.log_stash_logeer({**res, **g.logs}, 'acs_xml_api_logs')
            return res, 400

        uid_token_hash = hashlib.md5(uid_token.encode('utf-8')).hexdigest()
        ekyc_xml, code = ProfileModel.getKYCXMLFromAPI(uid_token_hash, user, 'acs_xml_api_logs')
        
        if code == 404:
            '''retry one more time if fails'''
            ekyc_xml, code = ProfileModel.getKYCXMLFromAPI(uid_token_hash, user, 'acs_xml_api_logs')
        
        if code == 200:
            res = {'step':'served', 'contentLength':len(ekyc_xml.get('data'))}
            rmq.log_stash_logeer({**res, **g.logs}, 'acs_xml_api_logs')
            return ekyc_xml, code
        else:
            rmq.log_stash_logeer({**ekyc_xml, **g.logs}, 'acs_xml_api_logs')
            return ekyc_xml, code
            
    except Exception as e:
        res = {STATUS:ERROR,  ERROR_DES:str(e)}
        rmq.log_stash_logeer({**res, **g.logs}, 'acs_xml_api_logs')
        res[ERROR_DES] = Errors.error("ERR_MSG_111")
        return res, 400

@bp.route('/kyc_info/1.0', methods=['POST'])
def kyc_info():
    g.logs['api_name'] = 'kyc_info/1.0'
    try:
        res, status_code = CommonLib.validate_token(request)
            
        if status_code == 200:
            user = res[0]
        else:
            log_data = res
            log_data['step'] = 'validation_err'
            rmq.log_stash_logeer({**log_data, **g.logs}, 'acs_xml_api_logs')
            res.pop('step', None)
            res.pop('err', None)
            return res, status_code
        g.logs['digilockerid'] = user
        users_data = get_users(user)
        user = users_data.get("digilockerid")
        uid_token = users_data.get('uid_token')
        '''uid_token must be in account i.e, aadhaar user only allowed to use this API'''
        if len(users_data) == 0 or uid_token is None:
            res = {'status': 'error', 'error_description': 'Data not found.'}
            rmq.log_stash_logeer({**res, **g.logs}, 'acs_xml_api_logs')
            return res, 400

        final_data = {'latest_kyc_on':'', 'xml_present':False}
        '''get kyc_date from users_profile'''
        users_profile_data = get_usersProfile(user)
        final_data['latest_kyc_on'] = users_profile_data.get('kyc_on', '')
        
        uid_token_hash = hashlib.md5(uid_token.encode('utf-8')).hexdigest()
        ekyc_xml, code = ProfileModel.getKYCXMLFromAPI(uid_token_hash, user, 'acs_xml_api_logs')
        
        if code == 404:
            '''retry one more time if fails'''
            ekyc_xml, code = ProfileModel.getKYCXMLFromAPI(uid_token_hash, user, 'acs_xml_api_logs')
        
        if code == 200 and ekyc_xml:
            final_data['xml_present'] = True
        
        return final_data, 200
            
    except Exception as e:
        res = {STATUS:ERROR,  ERROR_DES:str(e)}
        rmq.log_stash_logeer({**res, **g.logs}, 'acs_xml_api_logs')
        res[ERROR_DES] = Errors.error("ERR_MSG_111")
        return res, 400


def v1_without_auth(user):
    try:
        users_data = get_users(user)
        if len(users_data) == 0:
            return {'status': 'error', 'error_description': 'User data not found.'}, 400
        users_p_data = get_usersProfile(user)
        uid_token = users_data.get('uid_token')
        uid_token_hash = None
        if uid_token:
            uid_token_hash = hashlib.md5(uid_token.encode('utf-8')).hexdigest()
        ekyc = getKYCDataFromAPI(uid_token_hash, user)
        users_p_data = get_usersProfile(user)
        if len(users_p_data) == 0:
            return {'status': 'error', 'error_description': 'Profile data not found.'}, 400
             
        final_data = formatting_v1(users_data, users_p_data,ekyc)
        if type(final_data) == type({}) and final_data is not None:
            return final_data, 200
        else:
            res = {'status': 'error', 'error_description': 'Data not found.'}
            log_data = res
            rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return res, 400

    except Exception as e:
        res = {'status': 'error', 'error_description': 'An error occurred.'}  # Assuming your error structure
        log_data = res
        log_data['actual_error'] = str(e)
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return res, 400
    
def formatting_v1(userData={}, userProfileData={}, ekycData={}):
    try:
        response_data = {
            
            "mobile": userData.get('mobile_no') or '',
            "email": userData.get('email_id') or '',
            "gender": userProfileData.get('gender') or '',
            "full_name": userProfileData.get('name') or '',
            "photo" : ekycData.get('photo') or ''
                   
        }
        
        return response_data
    except Exception as e:
        print(str(e))
        return {}

'''
This API is substitute of PHP's API - users/getUserAadhaar, being used in IDS Worker.
2024-04-30 17:41:46 digilocker_tasks #153551 

'''
@bp.route('/getUserAadhaar/1.0', methods=['POST'])
def userAadhaar():
    try:
        res, status_code = CommonLib.validation_rules(request)
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            res['status'] = False
            return res, status_code
        
        users_data = get_users(user)
        user = users_data.get("digilockerid") if users_data.get("digilockerid") else user # this to be used further
        ky = user + '_aadhaarHash'
        from_redis = rs.get(key=ky)
        
        if from_redis:
            return {'status':True, 'aadhaarNumberHash':from_redis}, 200
            
        if len(users_data) == 0:
            return {'status': False, 'error_description': 'Data not found.'}, 400

        users_ext_data = getAccountExtentionDataByLockerid(user)
        md5_uid = users_ext_data.get('uid_md5')
        if md5_uid:
            rs.set(key=ky, value=md5_uid, ex=604800)
            return {'status':True, 'aadhaarNumberHash':md5_uid}, 200
        
        res = {STATUS: False, ERROR_DES: 'Data not found.'}
        return res, 400

    except Exception as e:
        res = {STATUS: False, ERROR_DES: Errors.error("ERR_MSG_111")}
        return res, 400
    
'''
    This API is substitute of PHP's API - profile/get_lockerid_aadhaar, being used in nsso forgot pin with aadhaar.
    2024-05-07  digilocker_tasks #155415 
'''
@bp.route('/get_lockerid_aadhaar', methods=['POST'])
def get_lockerid_aadhaar():
    try:
        res, status_code = CommonLib.validation_rules(request)
        if status_code == 200:
            user = res[0]  # this user will be used throughout now-onwards.
        else:
            res['status'] = False
            return res, status_code
        user_md5 = hashlib.md5(user.encode()).hexdigest()
        ky = user + '_exist'
        from_redis = rs.get(key=ky)
        if from_redis:
            return {'status':'success', 'data':from_redis}, 200
        users_ext_data = get_lockerid_aadhaar(user_md5)
        digilockerid = users_ext_data.get('digilockerid')
        if digilockerid:
            rs.set(key=ky, value=digilockerid, ex=604800)
            return {'status':'success', 'data':digilockerid}, 200
        
        res = {'status': 'error', 'error_description': 'No data found.'}
        return res, 400

    except Exception as e:
        res = {STATUS: False, ERROR_DES: Errors.error("ERR_MSG_111")}
        return res, 400
    
def get_lockerid_aadhaar(user_md5):
    try:
        res, code = MONGOLIB.accounts_eve_v2('users_info_extended', {"uid_md5": user_md5}, {})

        if code == 200 and res['status'] == 'success' and res.get('response') is not None:
            return res['response'][0]
        else:
            # log_data = {'status':'error', 'error_description':'ac ext data not found', 'step':'get_ac_extension_coll'}
            # rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
            return {}
    except Exception as e:
        log_data = {'status':'error', 'error_description':str(e), 'step':'exception while get ac_extension_coll'}
        rmq.log_stash_logeer({**log_data, **g.logs}, rmq_queue)
        return {}    