from datetime import datetime
import inspect
import json
import logging
import re
import hashlib
import time
import traceback
import uuid
from lib.commonlib_auth import CommonLib
from lib.constants_auth import *
from lib.mongolib import MongoLib
from lib.redislib import RedisLib
from lib.orglib import OrgLib
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
from flask import g, request
import ast
from pythonjsonlogger import jsonlogger


logs_queue = 'org_logs_PROD'
logarray = {}

RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
ORGLIB = OrgLib()
MONGOLIB = MongoLib()
REDISLIB = RedisLib()
current_date = datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-AUTH-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

class Validations:
    def __init__(self):
        self.test = 's'
        self.dept_name = ""
        self.description = ""

    def is_valid_id(self, id):
        pattern = r'^[a-zA-Z0-9\-]{32}$'
        return re.fullmatch(pattern, id)

    def is_valid_did(self, id):
        try:
            pattern = r'^[a-zA-Z0-9\-]{36}$'
            return re.fullmatch(pattern, id)
        except Exception:
            return False
        
    def is_valid_dept(self, id):
        try:
            pattern = r'^[a-zA-Z0-9\-]{32}$'
            return re.fullmatch(pattern, id)
        except Exception:
            return False

    def is_valid_date(self, date):
        if date is not None:
            try:
                datetime.strptime(date, D_FORMAT)
                return True
            except Exception:
                return
            
    def is_valid_email(self, email_id):
        pattern = r"^\S+@\S+\.\S+$"
        return re.match(pattern, email_id)
    
    def is_valid_pin(self, pin):
        pattern = r'^\d{6}$'
        return re.match(pattern, pin)

    def is_valid_pan(self, pan):
        pattern = r"^[A-Z]{5}\d{4}[A-Z]$"
        return re.match(pattern, pan)

    def is_valid_mobile(self, number):
        pattern = r"^\d{10}$"
        return re.match(pattern, str(number))
    
    def is_valid_cin(self, code, flag = False):
        if flag:
            query = {'cin': code}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_163')}, 406 # type: ignore
        pattern = r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$"
        check = re.match(pattern, str(code))
        status = SUCCESS if check else ERROR
        code = 200 if check else 401
        return {STATUS: status, ERROR_DES: Errors.error('ERR_MSG_148')}, code
    
    def is_valid_gstin(self, code):
        pattern = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'
        return re.match(pattern, str(code))
        
    def is_valid_udyam_number(self, code, flag=False):
        if flag:
            query = {'cin': code}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_167')}, 422 # type: ignore
        pattern = r"^UDYAM-[A-Z]{2}-\d{2}-\d{7}$"
        check = re.match(pattern, str(code))
        status = SUCCESS if check else ERROR
        code = 200 if check else 401
        return {STATUS: status, ERROR_DES: Errors.error('ERR_MSG_160')}, code

    def validate_string(self, name, string):
        if string != None and len(string) == 0:
            return 400, {'status': 'error', 'err_code': 128, 'msg': "%s is empty." % name}
        elif string != None and type(string) != type(""):
            return 400, {'status': 'error', 'err_code': 129, 'msg': "%s should be string not %s" % (name, str(type(string)))}
        elif name == "digilocker_id" and not self.is_valid_did(string):
            return 400, {'status': 'error', 'err_code': 130, 'msg': Errors.error("ERR_MSG_138")}
        elif name == 'din' and string != None and len(string) not in (8, 10):
            return 400, {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}
        return 200, string
    
    def validate_date(self, name, date):
        if date == None or len(date) == 0:
            return 200, datetime.now().strftime(D_FORMAT)
        elif type(date) != type(""):
            return 400, {'status': 'error', 'err_code': 126, 'msg': "%s should be string not %s" % (name, str(type(date)))}
        else:
            try:
                date_time = datetime.strptime(date, D_FORMAT)
                return 200, date_time.strftime(D_FORMAT)
            except Exception as dateFormattingError:
                return 400, {'status': 'error', 'err_code': 127, 'msg': "validate_date: failed to parse %s ~ %s" % (name, str(dateFormattingError))}

    def validate_org_info(self, data):
        filtered_data = {}
        status, res = self.validate_string('digilocker id', data.get('digilocker_id'))
        if status == 400:
            return status, res
        filtered_data['digilocker_id'] = res
        status, res = self.validate_string('din', data.get('din'))
        if status == 400:
            return status, res
        filtered_data['din'] = res
        is_active = data.get('is_active')
        status, res = self.validate_string('is active', is_active)
        if status == 400:
            return status, res
        filtered_data["is_active"] = res
        added_on = data.get('added_on')
        status, res = self.validate_date('added on', added_on)
        if status == 400:
            return status, res
        filtered_data["added_on"] = res
        if is_active == 'N':
            status, res = self.validate_date('deactivated on', data.get('deactivated_on'))
            if status == 400:
                return status, res
            filtered_data["deactivated_on"] = res
        return 200, filtered_data

    def validate_org_info_list(self, data):
        if len(data) == 0:
            return 400, {'status': 'error', 'err_code': 128, 'msg': "dir info is empty"}
        else:
            v_list = []
            for value in data:
                status, res = self.validate_org_info(value)
                if status == 400:
                    return status, res
                v_list.append(res)
            return 200, v_list

    def validate_dict(self, data):
        if data != None:
            if len(data) == 0:
                return 400, {'status': 'error', 'err_code': 128, 'msg': "dir info is empty"}
            elif type(data) == type({}):
                status, res = self.validate_org_info(data)
                if status == 400:
                    return status, res
                return status, [res]
            elif type(data) == type([]):
                return self.validate_org_info_list(data)
            elif type(data) == type(''):
                try:
                    data = json.loads(data)
                    return self.validate_dict(data)
                except Exception:
                    return 400, {'status': 'error', 'err_code': 128, 'msg': "Invalid format for dir info"}
        return 200, None

    def verify_name(self, request):
        ''' Validate otp details received over http request '''
        name = CommonLib.filter_input(request.values.get('name'))
        original_name = CommonLib.filter_input(
            request.values.get("original_name"))
        try:
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif name[0] is None or name[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_101")}, 400
            if original_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "original_name", RESPONSE: original_name[0]}, 400
            elif original_name[0] is None or original_name[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_102")}, 400
            return {STATUS: SUCCESS, "name": name[0], "original_name": original_name[0]}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::verify_name:' + str(e)}, 400

    def verify_director(self, request):
        ''' Validate otp details received over http request '''
        name = CommonLib.filter_input(request.values.get('name'))
        cin = CommonLib.filter_input(request.values.get("cin"))
        din = CommonLib.filter_input(request.values.get("din"))
        try:
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif name[0] is None or name[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_101")}, 400
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            elif not cin[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_148")}, 400
            res, status_code = self.is_valid_cin(cin[0], True)
            if status_code != 200:
                return res, status_code
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: din[0]}, 400
            elif din[0] is None or din[0] == "" or len(din[0]) != 8:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_132")}, 400
            return {STATUS: SUCCESS, "name": name[0], "cin": cin[0], "din": '00'+din[0]}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::verify_director: ' + str(e)}, 400

    def activity_insert(self, ac_type,subject,doc_name,user):
        ''' Validate activity insert'''
        ac_type = CommonLib.filter_input(ac_type)
        subject = CommonLib.filter_input(subject)
        doc_name = CommonLib.filter_input(doc_name)
        user = CommonLib.filter_input(user)
        try:
            if ac_type[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "type", RESPONSE: ac_type[0]}, 400
            elif ac_type[0] is None or ac_type[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_153")}, 400
            if subject[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "subject", RESPONSE: subject[0]}, 400
            elif subject[0] is None or subject[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_154")}, 400
            if doc_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "doc_name", RESPONSE: doc_name[0]}, 400
            elif doc_name[0] is None or doc_name[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_155")}, 400
            if user[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "user", RESPONSE: user[0]}, 400
            elif user[0] is None or not self.is_valid_did(user[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_119")}, 400
            
            post_data = {
                "activity_id" : int(time.time()),
                "user" : user[0],
                "affecteduser" : user[0],
                "timestamp" : str(int(time.time())),
                "type" : ac_type[0],
                "priority" : 40,
                "app" : 'files',
                "subject" : subject[0],
                "subjectparams" : '',
                "message" : '',
                "messageparams" : 'a:0:{M}',
                "file" : doc_name[0],
                "link" : '',
            }
            return {STATUS: SUCCESS, "post_data": post_data}, 200
        
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::activity_insert:' + str(e)}, 400

    def activity_fetch(self,request):
        org_id = CommonLib.filter_input(request.args.get('org_id'))
        try:
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org id", RESPONSE: org_id[0]}, 400
            elif org_id[0] != None and not self.is_valid_did(org_id[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            return {STATUS: SUCCESS,"org_id":org_id[0]},200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::activity_fetch:' + str(e)}, 400

    def hmac_authentication(self, request):
        ''' Validate hmac details received over http request '''
        return {STATUS: SUCCESS, MESSAGE: 'Authenticated user found!'}, 200
        
        client_id = CommonLib.filter_input(request.headers.get("client_id"))
        ts = CommonLib.filter_input(request.headers.get("ts"))
        hmac = CommonLib.filter_input(request.headers.get("hmac"))
        try:
            if client_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "client_id", RESPONSE: client_id[0]}, 400
            elif not client_id[0]:
                return {STATUS: ERROR, ERROR_DES: "Invalid client_id"}, 400
            if ts[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "ts", RESPONSE: ts[0]}, 400
            elif not ts[0]:
                return {STATUS: ERROR, ERROR_DES: "Invalid ts"}, 400
            if hmac[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "hmac", RESPONSE: hmac[0]}, 400
            elif not hmac[0]:
                return {STATUS: ERROR, ERROR_DES: "Invalid hmac"}, 400
            # creating hmac on server side stored secret
            plain_text_key_created = CONFIG['credentials'].get(client_id[0], '') + client_id[0] + ts[0]
            key_created = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            if hmac[0] == key_created:
                return {STATUS: SUCCESS, MESSAGE: 'Authenticated user found!'}, 200
            else:
                return{STATUS: ERROR, ERROR_DES: 'Unauthorised Access'}, 401

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::authentication:' + str(e)}, 400

    def validate_org_details(self, request, req_type='get'):
        org_alias = CommonLib.filter_input(request.json.get('org_alias'))
        org_type = CommonLib.filter_input(request.json.get('org_type'))
        name = CommonLib.filter_input(request.json.get('name'))
        pan = CommonLib.filter_input(request.json.get('pan'))
        mobile = CommonLib.filter_input(request.json.get('mobile'))
        email = CommonLib.filter_input(request.json.get('email'))
        d_incorporation = CommonLib.filter_input(request.json.get('d_incorporation'))
        roc = CommonLib.filter_input(request.json.get('roc'))
        icai = CommonLib.filter_input(request.json.get('icai'))
        din = CommonLib.filter_input(request.json.get('din'))
        cin = CommonLib.filter_input(request.json.get('cin'))
        gstin = CommonLib.filter_input(request.json.get('gstin'))
        dir_info = request.json.get('dir_info')
        authorization_letter = request.json.get('authorization_letter')
        is_authorization_letter = CommonLib.filter_input(request.json.get('is_authorization_letter'))
        consent = request.json.get('consent')
        ccin = None
        udyam = None
        try:
            if org_alias[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org alias", RESPONSE: org_alias[0]}, 400
            elif (org_alias[0] != None and org_alias[0] != '') and not org_alias[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_124")}, 400
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif (name[0] != None and name[0] != '') and not name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_125")}, 400
            if org_type[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org_type", RESPONSE: org_type[0]}, 400
            elif (org_type[0] != None and org_type[0] != '') and not org_type[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_172")}, 400
            if pan[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "pan", RESPONSE: pan[0]}, 400
            elif (pan[0] != None and pan[0] != '') and not self.is_valid_pan(pan[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif (mobile[0] != None and mobile[0] != '') and not self.is_valid_mobile(mobile[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if email[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "email", RESPONSE: email[0]}, 400
            elif (email[0] != None and email[0] != '') and not self.is_valid_email(email[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_171")}, 400
            if d_incorporation[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date of incorporation", RESPONSE: d_incorporation[0]}, 400
            elif (d_incorporation[0] != None and d_incorporation[0] != '') and not self.is_valid_date(d_incorporation[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_152")}, 400
            if roc[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "roc", RESPONSE: roc[0]}, 400
            elif (roc[0] != None and roc[0] != '') and not roc[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_174")}, 400
            if icai[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "icai", RESPONSE: icai[0]}, 400
            elif (icai[0] != None and icai[0] != '') and len(icai[0]) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_176")}, 400
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: din[0]}, 400
            elif (din[0] != None and din[0] != '') and len(din[0]) != 8:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            if authorization_letter and len(authorization_letter) < 32:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_177")}, 400
            if is_authorization_letter[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "is_authorization_letter", RESPONSE: din[0]}, 400
            if is_authorization_letter[0] != None and not is_authorization_letter[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_179")}, 400
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            elif not cin[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_148")}, 400
            elif req_type == 'create':
                if org_type[0] in ['LLP','llp']:
                    res, status_code = self.is_valid_cin(cin[0], True)
                    if status_code != 200:
                        return res, status_code
                    ccin = cin[0]
                if org_type[0] in ['MSME', 'msme']:
                    if not cin[0]:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_160")}, 400
                    res, status_code = self.is_valid_udyam_number(cin[0], True)
                    if status_code != 200:
                        return res, status_code
                    udyam = cin[0]
                if org_type[0] in ['PAN', 'pan']:
                    query = {'cin': pan[0]}
                    res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
                    if status_code == 200 and len(res[RESPONSE]) > 0:
                        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_163')}, 406 # type: ignore
                    if not consent or len(consent) < 20:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_182")}, 400
                    
                    if not name[0]:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_125")}, 400
                    if not self.is_valid_date(d_incorporation[0]):
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_152")}, 400
                    if not self.is_valid_pan(pan[0]):
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
                    if cin[0] != pan[0]: 
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_148")}, 400
                    res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], {'cin': cin[0]}, {}, limit=500)
                    if status_code == 200 and len(res[RESPONSE]) > 0:
                        return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_178')}, 422 # type: ignore
            if gstin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "gstin", RESPONSE: gstin[0]}, 400
            elif (gstin[0] != None and gstin[0] != '') and not self.is_valid_gstin(gstin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_150")}, 400
            status, res = self.validate_dict(dir_info)
            if status == 400:
                return res, status
            dir_info = res
            post_data = {}
            if org_alias[0]:
                post_data['org_alias'] = org_alias[0]
            if org_type[0]:
                post_data['org_type'] = org_type[0].lower()
            if name[0]:
                post_data['name'] = name[0].upper()
            if pan[0]:
                post_data['pan'] = pan[0].upper()
            if ccin:
                post_data['ccin'] = ccin.upper()
            if udyam:
                post_data['udyam'] = udyam.upper()
            if mobile[0]:
                post_data['mobile'] = mobile[0]
            if email[0]:
                post_data['email'] = email[0].lower()
            if d_incorporation[0]:
                post_data['d_incorporation'] = d_incorporation[0]
            if dir_info[0]['digilocker_id']: # type:ignore
                post_data['created_by'] = dir_info[0]['digilocker_id'] # type:ignore
            if req_type == 'create':
                post_data['created_on'] = datetime.now().strftime(D_FORMAT)
            if din[0]:
                post_data['din'] = din[0]
            if cin[0]:
                post_data['cin'] = cin[0].upper()
            if gstin[0]:
                post_data['gstin'] = gstin[0].upper()
            if roc[0]:
                post_data['roc'] = roc[0]
            if icai[0]:
                post_data['icai'] = icai[0]
            if dir_info:
                post_data['dir_info'] = dir_info
            if authorization_letter:
                post_data['authorization_letter'] = authorization_letter
            if consent:
                post_data['consent'] = consent
            if is_authorization_letter[0]:
                post_data['is_authorization_letter'] = is_authorization_letter[0].upper()
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:validate_org_details:: ' + str(e)}, 500

    def validate_get_org_details(self, request):
        org_id = CommonLib.filter_input(request.values.get('org_id'))
        org_alias = CommonLib.filter_input(request.values.get('org_alias'))
        pan = CommonLib.filter_input(request.values.get('pan'))
        mobile = CommonLib.filter_input(request.values.get('mobile'))
        created_by = CommonLib.filter_input(request.values.get('created_by'))
        din = CommonLib.filter_input(request.values.get('din'))
        cin = CommonLib.filter_input(request.values.get('cin'))
        gstin = CommonLib.filter_input(request.values.get('gstin'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))

        try:
            filter_data = {}
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org id", RESPONSE: org_id[0]}, 400
            elif org_id[0] != None and not self.is_valid_did(org_id[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            elif org_id[0] != None:
                filter_data["org_id"] = org_id[0]
            if org_alias[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org alias", RESPONSE: org_alias[0]}, 400
            elif org_alias[0] != None and not org_alias[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_124")}, 400
            elif org_alias[0] != None:
                filter_data["org_alias"] = org_alias[0]
            if pan[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "pan", RESPONSE: pan[0]}, 400
            elif pan[0] != None and not self.is_valid_pan(pan[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            elif pan[0] != None:
                filter_data["pan"] = pan[0]
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif mobile[0] != None and not self.is_valid_mobile(mobile[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            elif mobile[0] != None:
                filter_data["mobile"] = mobile[0]
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: din[0]}, 400
            elif din[0] != None and len(din[0]) != 8:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            elif din[0] != None:
                filter_data["din"] = din[0]
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            elif cin[0]:
                c_status_code = self.is_valid_cin(cin[0])
                u_status_code = self.is_valid_udyam_number(cin[0])
                if c_status_code[1] != 200 and u_status_code[1] != 200 and cin[0] != 10:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_168")}, 400
                filter_data["cin"] = cin[0]
            if gstin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "gstin", RESPONSE: gstin[0]}, 400
            elif gstin[0] != None and not self.is_valid_gstin(gstin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_150")}, 400
            elif gstin[0] != None:
                filter_data["gstin"] = gstin[0]
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0]:
                if not self.is_valid_did(digilockerid[0]):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
                else:
                    filter_data["digilockerid"] = digilockerid[0]
            return {
                STATUS: SUCCESS,
                "post_data": filter_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:validate_get_org_details:: ' + str(e)}, 500

    def is_valid_cin_v2(self, request, org_id):
        try:
            input_data_raw = request.get_data().decode("utf-8")
            input_data = json.loads(input_data_raw)
            cin_no = input_data.get("cin")
            cin_name = input_data.get("cin_name")
            cin_decrypted = CommonLib.aes_decryption_v2(cin_no, org_id[:16])
            name_decrypted = CommonLib.aes_decryption_v2(cin_name, org_id[:16])
            cin = cin_decrypted if cin_decrypted is not None else cin_no
            name = name_decrypted if name_decrypted is not None else cin_name
            if not cin or not self.is_valid_cin(cin):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_148")}, 400
            if not name :
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_208")}, 400
            query = {'ccin': cin}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_163')}, 406
            else:
                return {STATUS: SUCCESS, 'cin': cin, 'name': name}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_cin_v2:' + str(e)}, 400

    def is_valid_udyam_v2(self, request, org_id):
        udyam_number = CommonLib.filter_input(request.values.get('udyam_number'))
        mobile = CommonLib.filter_input(request.values.get('mobile'))
        udyam_number_decrypted = CommonLib.aes_decryption_v2(udyam_number[0], org_id[:16])
        mobile_decrypted = CommonLib.aes_decryption_v2(mobile[0], org_id[:16])
        mobile = mobile_decrypted if mobile_decrypted is not None else mobile
        udyam_number = udyam_number_decrypted if udyam_number_decrypted is not None else udyam_number
        try:
            if mobile == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile}, 400
            elif not mobile or not self.is_valid_mobile(mobile):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if udyam_number == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "udyam_number", RESPONSE: udyam_number}, 400
            elif not udyam_number or not self.is_valid_udyam_number(udyam_number):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_160")}, 400
            query = {'udyam': udyam_number}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)          
            if status_code == 200:
                log_data = {RESPONSE: Errors.error('ERR_MSG_167')}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_167')}, 406
            else:
                log_data = {RESPONSE: 'Udyam number and mobile successfully decrypted'}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
                return {STATUS: SUCCESS, 'mobile': mobile ,'udyam_number': udyam_number}, 200
        except Exception as e:
            log_data = {RESPONSE: e}
            logarray.update(log_data)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_udyam')
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:get_udcer:: ' + str(e)}, 400

    def is_valid_gstin_v2(self, request, org_id):
        try:
            gstin_enc = CommonLib.filter_input(request.values.get('gstin'))
            name_enc = CommonLib.filter_input(request.values.get('name'))
            gstin_decrypted = CommonLib.aes_decryption_v2(gstin_enc[0], org_id[:16])
            name_decrypted = CommonLib.aes_decryption_v2(name_enc[0], org_id[:16])
            gstin = gstin_decrypted if gstin_decrypted is not None else gstin_enc
            name = name_decrypted if name_decrypted is not None else name_enc
            if not gstin or not self.is_valid_gstin(gstin):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_150")}, 400
            if not name :
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            query = {'gstin': gstin}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                log_data = {RESPONSE: Errors.error('ERR_MSG_212')}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_gstin')
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_212')}, 406
            else:
                log_data = {RESPONSE: 'GSTIN name and number successfully decrypted'}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_gstin')
                return {STATUS: SUCCESS, 'gstin': gstin ,'name': name}, 200
        except Exception as e:
            log_data = {RESPONSE: e}
            logarray.update(log_data)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_gstin')
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_gstin:' + str(e)}, 400

    def create_org_details(self, request):
        ''' Validate org details received over http request '''

        keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        org_id = CommonLib.filter_input(request.json.get('txn', ''))[0]
        if len(org_id) != 36:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_133")}, 400
        res, status_code = self.validate_org_details(request, 'create')
        if status_code != 200:
            return res, status_code
        did = res["post_data"]['dir_info'][0]['digilocker_id']
    
        if True not in [res["post_data"].get(key) != None for key in keys]:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400

        access_post_data = {
            'org_id': org_id,
            'digilockerid': did,
            'access_id': hashlib.md5((org_id+did).encode()).hexdigest(),
            'is_active': res["post_data"]['dir_info'][0]['is_active'],
            'rule_id': 'ORGR001',
            'designation': 'director',
            'updated_by': did,
            'updated_on': datetime.now().strftime(D_FORMAT)

        }
        return {STATUS: SUCCESS, 'post_data': {'org_id': org_id, **res["post_data"]}, 'access_post_data': access_post_data}, status_code
    
    def create_org_permission(self, request):
        ''' Validate org permission received over http request '''
        fn_id = self.get_prmsonId(str(uuid.uuid4()))
        fn_name = CommonLib.filter_input(request.values.get('fn_name'))
        fn_description = CommonLib.filter_input(request.values.get('fn_description'))
        valid_till = CommonLib.filter_input(request.values.get('valid_till'))
        if fn_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
        access_post_data = {
            'fn_id': fn_id,
            'fn_name': fn_name[0],
            'fn_description': fn_description[0],
            'created_on': datetime.now().strftime(D_FORMAT),
            'valid_till': datetime.now().strftime(D_FORMAT)
            }
        
        return access_post_data, 200
    
    def user_org_permission(self, request):
        ''' Validate org permission received over http request '''
        fn_name = CommonLib.filter_input(request.values.get('fn_name'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        if digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if fn_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
        
        access_post_data = {
            'fn_name': fn_name[0],
            'digilockerid': digilockerid[0]
            }
        
        return access_post_data, 200

    def create_org_department(self, request):
        ''' Validate org department received over http request '''
        dept_id = self.get_deptId(str(uuid.uuid4()))
        dept_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))
        # Validate length of dept_name
        if dept_name[0]:
            dept_name_1 = CommonLib.aes_decryption_v2(dept_name[0], g.org_id[:16])
            if dept_name_1 is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
            
        if len(dept_name_1) > 100:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_209")}, 400
        
        description_1 = CommonLib.aes_decryption_v2(description[0], g.org_id[:16])
        # Validate length of description
        if len(description_1) > 250:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_210")}, 400
        
        
        access_post_data = {
            'name': dept_name_1,
            'dept_id': hashlib.md5((dept_id).encode()).hexdigest(),
            'description': description_1,

        }
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
    
    def update_org_depart(self, request):
       
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        dept_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))
        if dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        if dept_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
        access_post_data = {
            'dept_id': dept_id[0],
            'name': dept_name[0],
            'description': description[0],

        }
        return {STATUS: SUCCESS, 'access_post_data': access_post_data},200
    
    def access_id_pool_user(self, request):
       
        access_id = CommonLib.filter_input(request.values.get('access_id'))
        if access_id[0] and not self.is_valid_dept(access_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        if access_id[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_204")}, 400
        
        return {STATUS: SUCCESS, 'access_id': access_id[0]},200
    
    def org_user_profile_details(self, request):
       
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))

        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0]:
            digilocker_id = CommonLib.aes_decryption_v2(digilockerid[0], g.org_id[:16])
            if digilocker_id is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_218")}, 400
            elif not self.is_valid_did(digilocker_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        
            return {STATUS: SUCCESS, 'digilockerid': digilocker_id},200
        
    def org_admin_profile_details(self, request):
       
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))

        if g.role != "ORGR001":
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_219")}, 400

        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0]:
            digilocker_id = CommonLib.aes_decryption_v2(digilockerid[0], g.org_id[:16])
            if digilocker_id is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_218")}, 400
            elif not self.is_valid_did(digilocker_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            
            return {STATUS: SUCCESS, 'digilockerid': digilocker_id},200
    
    def default_user_details(self, request):
       
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        if digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if digilockerid[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        post_data = []
        for access_rule in g.org_access_rules:
            if digilockerid[0] == access_rule.get("digilockerid") and not access_rule.get("dept_id") and not access_rule.get("sec_id") and not access_rule.get("user_type"):
                if access_rule.get("rule_id") != "ORGR001":
                    post_data.append({
                        "user_type":"default",
                        "access_id": hashlib.md5((g.org_id+digilockerid[0]+g.org_id).encode()).hexdigest(),
                        "access_id1": access_rule.get("access_id")
                        })
                else:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_217")}, 400
            elif digilockerid[0] == access_rule.get("digilockerid") and access_rule.get("user_type"):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_215")}, 400
            
        return {STATUS: SUCCESS, 'post_data': post_data, 'digilockerid': digilockerid[0]},200
    
    def remove_default_user_details(self, request):
       
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        if digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if digilockerid[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        post_data = []
        for access_rule in g.org_access_rules:
            if digilockerid[0] == access_rule.get("digilockerid") and not access_rule.get("dept_id") and not access_rule.get("sec_id") and not access_rule.get("user_type"):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_216")}, 400
            elif digilockerid[0] == access_rule.get("digilockerid") and access_rule.get("user_type") and not access_rule.get("dept_id") and not access_rule.get("sec_id") :
                
                post_data.append({
                    "user_type": None,
                    "access_id": hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest(),
                    "access_id1": access_rule.get("access_id")
                    })
            
        return {STATUS: SUCCESS, 'post_data': post_data, 'digilockerid': digilockerid[0]},200
    
    def inactive_org_department_view(self, request):
        ''' Validate org department received over http request '''

        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        if dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        
        all_sections_inactive = True
        any_section_present = False
        access_post_data = []
        access_id = None
        for access_rule in g.org_access_rules:
            if access_rule.get('dept_id') == dept_id[0] and access_rule.get('sec_id') is None:
                access_id = access_rule.get('access_id')
                access_post_data.append({
                'is_active': "N",
                'dept_id': dept_id[0],
                'access_id': access_id,
                'updated_on': datetime.now().strftime(D_FORMAT)
                })
            
            if access_rule.get('dept_id') == dept_id[0]:
                if 'sec_id' in access_rule:
                    any_section_present = True
                    if access_rule.get('is_active') != "N":
                        all_sections_inactive = False
        
        if not any_section_present:
            access_post_data.append({
                'is_active': "N",
                'dept_id': dept_id[0],
                'access_id': access_id,
                'updated_on': datetime.now().strftime(D_FORMAT)
            })
            return {'status': 'SUCCESS', 'access_post_data': access_post_data}, 200 
        
        if not all_sections_inactive:
            return {'status': 'ERROR', 'error_description': "All Sections are not inactive of this department"}, 400
        
        return {'status': 'SUCCESS', 'access_post_data': access_post_data}, 200
        
    def inactive_to_active_org_department_view(self, request):
        ''' Validate org department received over http request '''

        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        if dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        
        for a, b in g.dept_details.items():
            if b.get('dept_id') == dept_id[0] and b.get('is_active') != "N":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_203")}, 400

        access_post_data =[]
        for access_rule in g.org_access_rules:
            if access_rule.get('dept_id') == dept_id[0] and access_rule.get('sec_id') is None:
                access_id = access_rule.get('access_id')
        
                access_post_data.append({
                'is_active': "Y",
                'dept_id': dept_id[0],
                'access_id': access_id,
                'updated_on': datetime.now().strftime(D_FORMAT)
            })
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
        
        
    
    def update_org_permission(self, request):
       
        fn_id = CommonLib.filter_input(request.values.get('fn_id'))
        fn_name = CommonLib.filter_input(request.values.get('fn_name'))
        fn_description = CommonLib.filter_input(request.values.get('fn_description'))
        valid_till = CommonLib.filter_input(request.values.get('valid_till'))
        if fn_id[0] and not self.is_valid_did(fn_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1391")}, 400
        if fn_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1991")}, 400
        access_post_data = {
            'fn_id': fn_id[0],
            'fn_name': fn_name[0],
            'fn_description': fn_description[0],
            'created_on': datetime.now().strftime(D_FORMAT),
            'valid_till': datetime.now().strftime(D_FORMAT),

        }
        return {STATUS: SUCCESS, 'access_post_data': access_post_data},200

    def create_org_department_sec(self, request):
        ''' Validate org department received over http request '''

        # keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        org_id = self.get_txn(CommonLib.filter_input(request.json.get('txn', ''))[0])
        res, status_code = self.validate_org_details(request, 'create')
        dept_name = CommonLib.filter_input(request.values.get('dept_name'))
        sec_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))

        if status_code != 200:
            return res, status_code
        did = res["post_data"]['dir_info'][0]['digilocker_id']
    
        # if True not in [res["post_data"].get(key) != None for key in keys]:
            # return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400

        access_post_data = {
            'org_id': org_id,
            'digilockerid': did,
            'access_id': hashlib.md5((org_id+did).encode()).hexdigest(),
            'rule_id': 'ORGR001',
            'updated_by': did,
            'name': sec_name,
            'dept_name': dept_name,
            'description': description,
            'updated_on': datetime.now().strftime(D_FORMAT)

        }
        return {STATUS: SUCCESS, 'post_data': {'org_id': org_id, **res["post_data"]}, 'access_post_data': access_post_data}, status_code


    def create_org_department_section(self, request):
        ''' Validate org department section received over http request '''
        sec_id = self.get_secId(str(uuid.uuid4()))
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        sec_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))
        if dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400
        if sec_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_200")}, 400
       

        access_post_data = {
            'dept_id': dept_id[0],
            'sec_id': hashlib.md5((sec_id).encode()).hexdigest(),
            'name': sec_name[0],
            'description': description[0],

        }
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
    
    def update_org_department_section(self, request):
        ''' Validate org department section received over http request '''

        sec_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        if sec_name[0] == '':
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_200")}, 400

        access_post_data = {
            'sec_id': sec_id[0],
            'name': sec_name[0],
            'description': description[0]

        }
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
    
    def inactive_org_department_section(self, request):
        ''' Validate org department section received over http request '''

        
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        access_post_data = []
        for access_rule in g.org_access_rules:
            if access_rule.get('sec_id') == sec_id[0]:
                access_id = access_rule.get('access_id')
                access_post_data.append({
                    'is_active': "N",
                    'sec_id': sec_id[0],
                    'access_id': access_id,
                    'updated_on': datetime.now().strftime(D_FORMAT)

                })
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
    
    def inactive_to_active_org_department_section(self, request):
        ''' Validate org department section received over http request '''

        
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        for a, b in g.sec_details.items():
            if b.get('sec_id') == sec_id[0] and b.get('is_active') != "N":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_202")}, 400

        access_post_data = []
        for access_rule in g.org_access_rules:
            if access_rule.get('sec_id') == sec_id[0]:
                access_id = access_rule.get('access_id')
                access_post_data.append({
                    'is_active': "Y",
                    'sec_id': sec_id[0],
                    'access_id': access_id,
                    'updated_on': datetime.now().strftime(D_FORMAT)

                })
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200

    def update_org_department(self, request):
        ''' Validate org department received over http request '''

        # keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        org_id = self.get_txn(CommonLib.filter_input(request.json.get('txn', ''))[0])
        res, status_code = self.validate_org_details(request, 'create')
        dept_name = CommonLib.filter_input(request.values.get('name'))
        description = CommonLib.filter_input(request.values.get('description'))

        if status_code != 200:
            return res, status_code
        did = res["post_data"]['dir_info'][0]['digilocker_id']
    
        # if True not in [res["post_data"].get(key) != None for key in keys]:
            # return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400

        access_post_data = {
            'updated_by': did,
            'name': dept_name,
            'description': description,
            'updated_on': datetime.now().strftime(D_FORMAT)

        }
        return {STATUS: SUCCESS, 'post_data': {'org_id': org_id, **res["post_data"]}, 'access_post_data': access_post_data}, status_code

    def department_get_users(self, request):
        
        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        access_post_data = {
            'dept_id': dept_id[0],
         }
        if not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400
        
        return access_post_data, 200

    def assign_users_org_details(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        rule_name = CommonLib.filter_input(request.values.get('rule_name'))

        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0]:
            digilocker_id = CommonLib.aes_decryption_v2(digilockerid[0], g.org_id[:16])
            if digilocker_id is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_218")}, 400
            elif not self.is_valid_did(digilocker_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0]:
            deptid = CommonLib.aes_decryption_v2(dept_id[0], g.org_id[:16])
            if deptid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1351")}, 400
            elif not self.is_valid_dept(deptid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
            
        rolename = CommonLib.aes_decryption_v2(rule_name[0], g.org_id[:16])
          
        rule_id = Roles.rule_name(rolename)
        if not rule_id:
           return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_201")}, 400
        
        has_permission = False
        user_exists = False
        new_user_access_id = hashlib.md5((g.org_id+digilocker_id).encode()).hexdigest()
        new_user_dept_access_id = hashlib.md5((g.org_id+digilocker_id+deptid).encode()).hexdigest()
        # Logged In user validation
        if g.role == "ORGR001":
            has_permission = True
        for access_rule in g.org_access_rules:
            
            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y" and not access_rule.get('user_type'):
                user_exists = True
            if access_rule['access_id'] == new_user_dept_access_id:
                if access_rule['is_active'] == "Y":
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_186")}, 400
                elif access_rule['is_active'] == "N":
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_213")}, 400
                
                
        
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_187")}
            
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        
        post_data= {
        'org_id': g.org_id,
        'digilockerid': digilocker_id,
        'rule_id': rule_id,
        'dept_id': deptid,
        'is_active': "Y",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': new_user_dept_access_id
        }
        return post_data, 200
    
    def update_assign_users_org_details(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        rule_name = CommonLib.filter_input(request.values.get('rule_name'))
        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        rule_id = Roles.rule_name(rule_name[0])
        if not rule_id:
           return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_201")}, 400
        
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_dept_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]).encode()).hexdigest()
        post_data = []
        for access_rule in g.org_access_rules:
            
            # Logged In user validation
            if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001" and access_rule['is_active'] == "Y":
                has_permission = True
            if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                has_permission = True
            # New department user validation
            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "Y":
                user_exists = True
            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "N":
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_196")}
                
                return res, 400  
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_189")}
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data.append(
        {
        'rule_id': rule_id,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'updated_by': g.digilockerid,
        'access_id': new_user_dept_access_id
        }
        )
        return {'post_data': post_data, 'dept_id': dept_id[0], 'digilockerid':digilockerid[0]},200
    
    def revoke_assign_users_org_details(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))

        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0]:
            digilocker_id = CommonLib.aes_decryption_v2(digilockerid[0], g.org_id[:16])
            if digilocker_id is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_218")}, 400
            elif not self.is_valid_did(digilocker_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0]:
            deptid = CommonLib.aes_decryption_v2(dept_id[0], g.org_id[:16])
            if deptid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1351")}, 400
            elif not self.is_valid_dept(deptid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        
        has_permission = False
        user_exists = False
        new_user_access_id = hashlib.md5((g.org_id+digilocker_id).encode()).hexdigest()
        new_user_dept_access_id = hashlib.md5((g.org_id+digilocker_id+deptid).encode()).hexdigest()
        post_data = []
        for access_rule in g.org_access_rules:
            
            # Logged In user validation
            if g.role == "ORGR001":
                has_permission = True

            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y":
                if access_rule['rule_id'] == "ORGR001":
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_214")}, 400
                elif access_rule['rule_id'] != "ORGR001":
                    user_exists = True

            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "N":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_196")}, 400
                
            if access_rule['is_active'] == "Y" and access_rule['digilockerid'] ==  digilocker_id and access_rule.get('dept_id') == deptid and access_rule.get('sec_id'): 
                post_data.append({
                        
                        'is_active': "N",
                        'updated_on': datetime.now().strftime(D_FORMAT),
                        'updated_by': g.digilockerid,
                        'access_id': access_rule['access_id'],
                        'sec_id': access_rule.get('sec_id')
                })       
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_189")}
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data.append(
        {
        'is_active': "N",
        'updated_on': datetime.now().strftime(D_FORMAT),
        'updated_by': g.digilockerid,
        'access_id': new_user_dept_access_id
        }
        )
        return {'post_data': post_data, 'dept_id': deptid, 'digilockerid':digilocker_id},200
    
    def active_assign_users_org_details(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))

        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0]:
            digilocker_id = CommonLib.aes_decryption_v2(digilockerid[0], g.org_id[:16])
            if digilocker_id is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_218")}, 400
            elif not self.is_valid_did(digilocker_id):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0]:
            deptid = CommonLib.aes_decryption_v2(dept_id[0], g.org_id[:16])
            if deptid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1351")}, 400
            elif not self.is_valid_dept(deptid):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        
        # access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        # dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_dept_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]).encode()).hexdigest()

        for access_rule in g.org_access_rules:
            
            # Logged In user validation
            if g.role == "ORGR001":
                has_permission = True
            # if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001" and access_rule['is_active'] == "Y":
            #     has_permission = True
            # if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
            #     has_permission = True
            # New department user validation
            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y":
                user_exists = True
            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "Y":
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_186")}
                return res, 400
            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "N":
                user_exists = True  
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_189")}
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data = {
            'is_active': "Y",
            'updated_on': datetime.now().strftime(D_FORMAT),
            'updated_by': g.digilockerid,
            'access_id': new_user_dept_access_id
            }
        
        return {'post_data': post_data, 'dept_id': dept_id[0], 'digilockerid':digilockerid[0]},200
    
    def assign_users_org_section(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        rule_name = CommonLib.filter_input(request.values.get('rule_name'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        if sec_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "sec_id", RESPONSE: sec_id[0]}, 400
        elif sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1371")}, 400
        
        rule_id = Roles.rule_name(rule_name[0])
        if not rule_id:
           return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_201")}, 400
        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        sec_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]+sec_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        has_dept_permission = False
        user_exists_department = False
        
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_dept_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]).encode()).hexdigest()
        new_user_sec_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]+sec_id[0]).encode()).hexdigest()
        for access_rule in g.org_access_rules:
            # Logged In user validation
            if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001":
                
                has_permission = True
                has_dept_permission = True
            if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003"):
                has_permission = True
            if access_rule['access_id'] == sec_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003"):
                
                has_dept_permission = True
                
            # New department user validation
            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y" and not access_rule.get('revoked_on') and not access_rule.get('user_type'):
                
                user_exists = True
            if access_rule['access_id'] == new_user_dept_access_id and access_rule['is_active'] == "Y" and not access_rule.get('revoked_on'):
                user_exists_department = True
            
            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "Y" and not access_rule.get('revoked_on'):
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_195")}
                
                return res, 400
        
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_190")}
            
            return res, 400
        
        if not has_dept_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_191")}
            
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        # post_data_dept = {}
        # if not user_exists_department:
        #     post_data_dept = {
        # 'org_id': g.org_id,
        # 'digilockerid': digilockerid[0],
        # 'rule_id': "ORG002",
        # 'dept_id': dept_id[0],
        # 'is_active': "Y",
        # 'updated_by': g.digilockerid,
        # 'updated_on': datetime.now().strftime(D_FORMAT),
        # 'access_id': new_user_dept_access_id
        # }
         
        
        post_data= {
        'org_id': g.org_id,
        'digilockerid': digilockerid[0],
        'rule_id': rule_id,
        'dept_id': dept_id[0],
        'sec_id': sec_id[0],
        'is_active': "Y",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': new_user_sec_access_id
        }

        return {'post_data': post_data}, 200
	    
    
    def active_users_org_section(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        if sec_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "sec_id", RESPONSE: sec_id[0]}, 400
        elif sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400

        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        sec_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]+sec_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        has_dept_permission = False
        
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_sec_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]+sec_id[0]).encode()).hexdigest()
        dept_sec_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]).encode()).hexdigest()
        post_data = []
        for access_rule in g.org_access_rules:
            # Logged In user validation
            if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001" and access_rule['is_active'] == "Y":
                
                has_permission = True
                has_dept_permission = True
            if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                has_permission = True
            if access_rule['access_id'] == sec_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                
                has_dept_permission = True
                
            # New department user validation
            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y":
                
                user_exists = True

            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "Y":
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_195")}
                return res, 400
            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "N":
                user_exists = True
            if access_rule['is_active'] == "N" and access_rule['access_id'] == dept_sec_access_id: 
                post_data.append({
                        
                        'is_active': "Y",
                        'updated_on': datetime.now().strftime(D_FORMAT),
                        'updated_by': g.digilockerid,
                        'access_id': access_rule['access_id']
                        })    
        
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_197")}
            
            return res, 400
        
        if not has_dept_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_198")}
            
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data.append( {
        
        'is_active': "Y",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': new_user_sec_access_id
        })
        
        return {'post_data': post_data, 'dept_id': dept_id[0], 'sec_id': sec_id[0],'digilockerid':digilockerid[0]},200
    
    def update_role_users_org_section(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        rule_name = CommonLib.filter_input(request.values.get('rule_name'))
        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        if sec_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "sec_id", RESPONSE: sec_id[0]}, 400
        elif sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
        rule_id = Roles.rule_name(rule_name[0])
        if not rule_id:
           return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_201")}, 400

        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        sec_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]+sec_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        has_dept_permission = False
        
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_sec_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]+sec_id[0]).encode()).hexdigest()
        for access_rule in g.org_access_rules:
            # Logged In user validation
            if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001" and access_rule['is_active'] == "Y":
                
                has_permission = True
                has_dept_permission = True
            if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                has_permission = True
            if access_rule['access_id'] == sec_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                
                has_dept_permission = True
                
            # New department user validation
            # if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y":
                
            #     user_exists = True
            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "Y":
                user_exists = True
        
            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "N":
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_196")}
                
                return res, 400
        
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_197")}
            
            return res, 400
        
        if not has_dept_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_198")}
            
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data= {
        
        'rule_id': rule_id,
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': new_user_sec_access_id
        }
        return {'post_data': post_data, 'dept_id': dept_id[0], 'digilockerid':digilockerid[0],'sec_id':sec_id[0]},200
    
    def revoke_users_org_section(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        if digilockerid[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
        elif digilockerid[0] and not self.is_valid_did(digilockerid[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0] and not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1381")}, 400
        if sec_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "sec_id", RESPONSE: sec_id[0]}, 400
        elif sec_id[0] and not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1371")}, 400

        access_id = hashlib.md5((g.org_id+g.digilockerid).encode()).hexdigest()
        dept_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]).encode()).hexdigest()
        sec_access_id = hashlib.md5((g.org_id+g.digilockerid+dept_id[0]+sec_id[0]).encode()).hexdigest()
        has_permission = False
        user_exists = False
        has_dept_permission = False
        
        new_user_access_id = hashlib.md5((g.org_id+digilockerid[0]).encode()).hexdigest()
        new_user_sec_access_id = hashlib.md5((g.org_id+digilockerid[0]+dept_id[0]+sec_id[0]).encode()).hexdigest()
        for access_rule in g.org_access_rules:
            # Logged In user validation
            if access_rule['access_id'] == access_id and access_rule['rule_id'] == "ORGR001" and access_rule['is_active'] == "Y":
                
                has_permission = True
                has_dept_permission = True
            if access_rule['access_id'] == dept_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                has_permission = True
            if access_rule['access_id'] == sec_access_id and access_rule['rule_id'] in ("ORGR001", "ORGR003") and access_rule['is_active'] == "Y":
                
                has_dept_permission = True
                
            # New department user validation
            if access_rule['access_id'] == new_user_access_id and access_rule['is_active'] == "Y":
                
                user_exists = True
        
            if access_rule['access_id'] == new_user_sec_access_id and access_rule['is_active'] == "N":
                res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_196")}
                
                return res, 400
        
        if not has_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_197")}
            
            return res, 400
        
        if not has_dept_permission:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_198")}
            
            return res, 400
        
        if not user_exists:
            res = {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}
            return res, 400
        post_data= {
        
        'is_active': "N",
        'updated_by': g.digilockerid,
        'updated_on': datetime.now().strftime(D_FORMAT),
        'access_id': new_user_sec_access_id
        }
        return {'post_data': post_data, 'dept_id': dept_id[0], 'sec_id': sec_id[0], 'digilockerid':digilockerid[0]},200

    def section_department_org_details(self, request):
        
        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        access_post_data = {
            'dept_id': dept_id[0],
         }
        
        if dept_id[0] not in g.user_departments:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_192")}, 400
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
    
    def department_users(self, request):

        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        
        if dept_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
        elif dept_id[0]:
            deptid = CommonLib.aes_decryption_v2(dept_id[0], g.org_id[:16])
            if deptid is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_1351")}, 400
            
        # Allow access if the department ID matches the organization ID
        access_post_data = {
            'dept_id': deptid,
         }
        if deptid == g.org_id:
            return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200

        # Validate department ID
        if not self.is_valid_dept(deptid):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400

        access_id = hashlib.md5((g.org_id+g.digilockerid+g.org_id).encode()).hexdigest()

        # Determine permissions based on roles
        if g.role == "ORGR001":
            # Admin: Full permissions
            return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
        elif g.role in ("ORGR003", "ORGR002"):
            # Manager with specific user_type and matching access_id gets full permissions
            for access_rule in g.org_access_rules:
                user_type = access_rule.get('user_type')
                access_id_check = access_rule.get('access_id')
                rule_id = access_rule.get('rule_id')
                if deptid in g.user_departments:
                    return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
                elif user_type and access_id_check == access_id:
                    return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_192")}, 400
    
    def section_users(self, request):
        
        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        sec_id = CommonLib.filter_input(request.values.get('sec_id'))
        access_post_data = {
            'dept_id': dept_id[0],
            'sec_id': sec_id[0],
         }
        if not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400
        if not self.is_valid_dept(sec_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
        if dept_id[0] not in g.user_departments:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_192")}, 400
        
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200

    def section_count(self, request):
        
        
        dept_id = CommonLib.filter_input(request.values.get('dept_id'))
        access_post_data = {
            'dept_id': dept_id[0]
         }
        if not self.is_valid_dept(dept_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400
        if dept_id[0] not in g.user_departments:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_192")}, 400
        
        return {STATUS: SUCCESS, 'access_post_data': access_post_data}, 200

    def get_org_details(self, request):
        ''' Validate org details received over http request '''

        keys = ["org_id", "org_alias", "pan", "created_by", "mobile", "din", "cin", "gstin"]
        res, status_code = self.validate_get_org_details(request)
        if status_code != 200:
            return res, status_code
        if True not in [res["post_data"].get(key) != None for key in keys]:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400
        return {STATUS: SUCCESS, 'post_data': res["post_data"]}, status_code

    def update_org_details(self, request):
        '''  '''
        keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        org_id = CommonLib.filter_input(request.json.get('org_id') or request.args.get('org_id'))
        res, status_code = self.validate_org_details(request, 'update')
        if status_code != 200:
            return res, status_code
        if org_id[1] == 400:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org id", RESPONSE: org_id[0]}, 400
        elif org_id[0] != None and not self.is_valid_did(org_id[0]):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
        res["post_data"]["org_id"] = org_id[0]
        if True not in [res["post_data"].get(key) != None for key in keys]:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400
        return res, status_code

    def org_access_rules(self, request, operation = 'G'):
        ''' Validate org access rules received over http request '''
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid') or request.args.get('digilockerid'))
        org_id = CommonLib.filter_input(request.values.get('org_id') or request.args.get('org_id'))
        access_id = CommonLib.filter_input(request.values.get('access_id') or request.args.get('access_id'))
        rule_id = CommonLib.filter_input(request.values.get('rule_id') or request.args.get('rule_id'))
        updated_by = CommonLib.filter_input(request.values.get('updated_by'))
        is_active = CommonLib.filter_input(request.values.get('is_active'))

        try:
            if not digilockerid[0] and not org_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_126")}, 400
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "orgId", RESPONSE: org_id[0]}, 400
            elif org_id[0] != None and org_id[0] == '':
                if self.is_valid_did(org_id[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            if rule_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "rule_id", RESPONSE: rule_id[0]}, 400
            elif rule_id[0] != None and not rule_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_127")}, 400
            if access_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif access_id[0] != None and not access_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_170")}, 400
            if is_active[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "is_active", RESPONSE: is_active[0]}, 400
            elif is_active[0] != None and not is_active[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_169")}, 400
            if operation == 'C' and (not digilockerid[0] or not org_id[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_126")}, 400

            post_data = {
                'org_id': org_id[0],
                'digilockerid': digilockerid[0],
                'is_active': is_active[0] or "Y",
                'rule_id': rule_id[0],
                'updated_by': updated_by[0],
                'updated_on': datetime.now().strftime(D_FORMAT),
            }
            post_data['access_id'] = hashlib.md5((org_id[0]+ digilockerid[0]).encode()).hexdigest() if operation == 'C' else access_id[0]
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:org_access_rules:: ' + str(e)}, 400

    def set_pin_signup(self, request):
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        pin = request.values.get('pin')
        email = request.values.get('email')
        mobile = request.values.get('mobile')
        try:
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if not pin or len(pin) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_139")}, 400
            if mobile:
                mobile_dec = CommonLib.aes_decryption_v2(mobile,digilockerid[0][:16])
                if mobile_dec and not self.is_valid_mobile(mobile_dec):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_116")}, 400
            if email:
                email_dec = CommonLib.aes_decryption_v2(email,digilockerid[0][:16])
                if not email_dec or not self.is_valid_email(email_dec):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_171")}, 400
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_171")+"."}, 400 
            profile_data = {
                'digilockerid': digilockerid[0],
                'email_id': email_dec,
                'mobile_no': mobile_dec
            }
            pin_data = {
                'digilockerid': digilockerid[0],
                'pin': ORGLIB.get_hash_pwd(pin)
            }
            return {
                STATUS: SUCCESS,
                "profile_data": profile_data,
                "pin_data": pin_data
            }, 200
        except Exception as e:
           return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:set_pin_signup:: ' + str(e)}, 400
    
    
    def set_pin(self, request):
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        pin = request.values.get('pin')
        try:
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            
            '''getting pin in this format from view: 1|$2y$10$cyh.r/4avFbbs8g1PTlYg.LbsaG9BNbGE7n0Xzhk/IteptLhJCdka'''
            if pin is None or pin == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_139")}, 400

            post_data = {
                'digilockerid': digilockerid[0],
                'pin': pin
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
           return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:set_pin:: ' + str(e)}, 400
           
    
    def verify_pin(self, request):
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        pin = CommonLib.filter_input(request.values.get('pin'))
        try:
            if digilockerid[0] is None and pin[0] is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138") + 'or' +Errors.error("ERR_MSG_139")}, 400
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if pin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "pin", RESPONSE: pin[0]}, 400
            elif not pin[0] or not self.is_valid_pin(pin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_146")}, 400
            post_data = {
                'digilockerid': digilockerid[0],
                'pin': pin[0]
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_pin:: ' + str(e)}, 400

    def get_udcer(self, request):
        mobile = CommonLib.filter_input(request.values.get('mobile'))
        udyam_number = CommonLib.filter_input(request.values.get('udyam_number'))
        try:
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or not self.is_valid_mobile(mobile[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if udyam_number[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "udyam number", RESPONSE: udyam_number[0]}, 400
            elif not udyam_number[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_160")}, 400
            res, status_code = self.is_valid_udyam_number(udyam_number[0], True)
            if status_code != 200:
                return res, status_code
            TS = datetime.now().strftime(D_FORMAT)
            post_data = {
                "txnId": str(uuid.uuid4()),
                "format": "xml",
                "certificateParameters": {
                    "udyamNumber": udyam_number[0],
                    "mobileNumber": mobile[0]
                },
                "consentArtifact": {
                    "consent": {
                        "consentId": str(uuid.uuid4()),
                        "timestamp": TS,
                        "dataConsumer": {
                            "id": "string"
                        },
                        "dataProvider": {
                            "id": "string"
                        },
                        "purpose": {
                            "description": "string"
                        },
                        "user": {
                            "idType": "string",
                            "idNumber": "string",
                            "mobile": mobile[0],
                            "email": "abc@xyz.com"
                        },
                        "data": {
                            "id": "string"
                        },
                        "permission": {
                            "access": "string",
                            "dateRange": {
                                "from": TS,
                                "to": TS
                            },
                            "frequency": {
                                "unit": "string",
                                "value": 0,
                                "repeats": 0
                            }
                        }
                    },
                    "signature": {
                        "signature": "string"
                    }
                }
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:get_udcer:: ' + str(e)}, 400
        
    def get_txn(self, org_id):
        try:
            if len(org_id) == 36:
                res = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"],
                    {'org_id': org_id},
                    projection={'_id': 0, 'org_id': 1}
                )
                for data in res:
                    if data:
                        return str(uuid.uuid4())
                return org_id
            else:
                return str(uuid.uuid4())
        except Exception as e:
            return str(uuid.uuid4())
                

    def verify_pan(self, request, flag=False):
        txn_id = CommonLib.filter_input(request.values.get('txn'))
        pan = CommonLib.filter_input(request.values.get('pan'))
        name = CommonLib.filter_input(request.values.get('name'))
        d_incorporation = CommonLib.filter_input(request.values.get('d_incorporation'))
        try:
            if pan[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "pan", RESPONSE: pan[0]}, 400
            elif not pan[0] or not self.is_valid_pan(pan[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            
            if txn_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "txn_id", RESPONSE: txn_id[0]}, 400
            elif txn_id[0] != None and self.is_valid_did(txn_id[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_134")}, 400
            txn = txn_id[0]
            '''check if PAN already exists in db'''
            if flag:
                query = {'cin': pan[0]}
                res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
                if status_code == 200 and len(res[RESPONSE]) > 0:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_178')}, 406 # type: ignore
                
                txn = self.get_txn(txn_id[0])
                
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif not name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_125")}, 400
            if d_incorporation[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date of incorporation", RESPONSE: d_incorporation[0]}, 400
            elif (d_incorporation[0] != None and d_incorporation[0] != '') and not self.is_valid_date(d_incorporation[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_152")}, 400
            TS = datetime.now().strftime(D_FORMAT)
            post_data = {
                "txnId": str(uuid.uuid4()),
                "orgPan": pan[0],
                "verificationData": {
                    "orgName": name[0],
                    "doi": datetime.strptime(d_incorporation[0], D_FORMAT).strftime("%d-%m-%Y")
                },
                "consentArtifact": {
                    "consent": {
                        "consentId": "string",
                        "timestamp": "string",
                        "dataConsumer": {
                            "id": "string"
                        },
                        "dataProvider": {
                            "id": "string"
                        },
                        "purpose": {
                            "description": "string"
                        },
                        "user": {
                            "idType": "string",
                            "idNumber": "string",
                            "mobile": "9874563210",
                            "email": "demostest@gmail.com"
                        },
                        "data": {
                            "id": "string"
                        },
                        "permission": {
                            "access": "string",
                            "dateRange": {
                                "from": TS,
                                "to": TS
                            },
                            "frequency": {
                                "unit": "string",
                                "value": 0,
                                "repeats": 0
                            }
                        }
                    },
                    "signature": {
                        "signature": "string"
                    }
                }
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data,
                'txn_id': txn
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_pan:: ' + str(e)}, 400
             

    def verify_icai(self, request):
        member_id = CommonLib.filter_input(request.values.get('member_id'))
        name = CommonLib.filter_input(request.values.get('name'))
        dob = CommonLib.filter_input(request.values.get('dob'))
        try:
            if member_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "member_id", RESPONSE: member_id[0]}, 400
            elif not member_id[0] or len(member_id[0]) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_176")}, 400
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif not name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_101")}, 400
            if dob[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date of incorporation", RESPONSE: dob[0]}, 400
            elif (dob[0] != None and dob[0] != '') and not self.is_valid_date(dob[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("err_473")}, 400
            TS = datetime.now().strftime(D_FORMAT)
            post_data = {
                "txnId": str(uuid.uuid4()),
                "format": "xml",
                "certificateParameters": {
                    "memberid": member_id[0],
                    "FullName": name[0],
                    "DOB": datetime.strptime(dob[0], D_FORMAT).strftime("%d-%m-%Y")
                },
                "consentArtifact": {
                    "consent": {
                        "consentId": str(uuid.uuid4()),
                        "timestamp": TS,
                        "dataConsumer": {
                            "id": "string"
                        },
                        "dataProvider": {
                            "id": "string"
                        },
                        "purpose": {
                            "description": "string"
                        },
                        "user": {
                            "idType": "string",
                            "idNumber": "string",
                            "mobile": "9999999999",
                            "email": "abc@gmail.com"
                        },
                        "data": {
                            "id": "string"
                        },
                        "permission": {
                            "access": "string",
                            "dateRange": {
                                "from": TS,
                                "to": TS
                            },
                            "frequency": {
                                "unit": "string",
                                "value": 0,
                                "repeats": 0
                            }
                        }
                    },
                    "signature": {
                        "signature": "string"
                    }
                }
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_pan:: ' + str(e)}, 400
        

    def send_aadhaar_otp_valid(self, request):
        try:
            uid = request.values.get('uid')
            din = request.values.get('din')
            if uid is None or len(uid) != 12:
                return {STATUS: ERROR,  ERROR_DES: Errors.error('err_931')}, 400
            if din != None and len(din) != 8:
                return {STATUS: ERROR,  ERROR_DES: Errors.error('ERR_MSG_132')}, 400
            return [uid, din], 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:sendaadhaarOTP_valid::' + str(e)}, 400

    def valid_txn(self, txn):
        try:
            redis_txn = REDISLIB.get(txn + '_logID')
            if txn == redis_txn:
                REDISLIB.expire(txn + '_logID', 600)
                return True
            else:
                return False
        except Exception as e:
            return False
        
    def verify_aadhaar_otp_valid(self, request):
        try:
            uid = request.values.get('uid')
            txn = request.values.get('txn')  # to validate txn from redis
            otp = request.values.get('otp')
            
            # todo validation rules
            if otp is None or len(otp) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error('err_101')}, 400
            if uid is None or len(uid) != 12:
                return {STATUS: ERROR, ERROR_DES: Errors.error('err_931')}, 400
            if txn is None or len(txn) != 36:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_133')}, 400
            elif not self.valid_txn(txn):
                return {STATUS: ERROR, ERROR_DES: Errors.error('err_115')}, 400

            return [uid, txn, otp], 200
        except Exception as e:
            return 400, {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verifyaadhaarOTP::' + str(e)}

    def get_txn(self, org_id):
        try:
            if len(org_id) == 36:
                res = MONGOLIB.accounts_eve(
                    CONFIG["org_eve"]["collection_details"],
                    {'org_id': org_id},
                    projection={'_id': 0, 'org_id': 1}
                )
                for data in res:
                    if data:
                        return str(uuid.uuid4())
                return org_id
            else:
                return str(uuid.uuid4())
        except Exception as e:
            return str(uuid.uuid4())
    
    def get_deptId(self, dept_id):
        try:
            if len(dept_id) == 36:
                res = MONGOLIB.accounts_eve(
                    CONFIG["org_eve"]["collection_dept"],
                    {'dept_id': dept_id},
                    projection={'_id': 0, 'dept_id': 1}
                )
                for data in res:
                    if data:
                        return str(uuid.uuid4())
                return dept_id
            else:
                return str(uuid.uuid4())
        except Exception as e:
            return str(uuid.uuid4())
        
    def get_prmsonId(self, fn_id):
        try:
            if len(fn_id) == 36:
                res = MONGOLIB.accounts_eve(
                    CONFIG["org_eve"]["collection_func"],
                    {'fn_id': fn_id},
                    projection={'_id': 0, 'fn_id': 1}
                )
                for data in res:
                    if data:
                        return str(uuid.uuid4())
                return fn_id
            else:
                return str(uuid.uuid4())
        except Exception as e:
            return str(uuid.uuid4())
        
    def get_secId(self, sec_id):
        try:
            if len(sec_id) == 36:
                res = MONGOLIB.accounts_eve(
                    CONFIG["org_eve"]["collection_sec"],
                    {'sec_id': sec_id},
                    projection={'_id': 0, 'sec_id': 1}
                )
                for data in res:
                    if data:
                        return str(uuid.uuid4())
                return sec_id
            else:
                return str(uuid.uuid4())
        except Exception as e:
            return str(uuid.uuid4())
        
    ''' validation mobile otp'''  
    
    def send_otp_v1(self, request):
        mobile =  CommonLib.filter_input(request.values.get('mobile'))
       
        try: 
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or len(mobile[0]) != 10:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
           
            clientid = os.getenv('org_clientid')
            client_seret = os.getenv('org_client_secret')
            ts = str(int(time.time()))
            plain_text_key_created = client_seret + clientid + mobile[0] + ts
            hmac = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            return {
                STATUS: SUCCESS,
                "post_data": {
                    'mobile': mobile[0],
                    'clientid': clientid,
                    'ts': ts,
                    'hmac': hmac
                    
                },
                "headers": {}
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:send_otp_v1:: ' + str(e)}, 400
        

    
    def verify_otp_v1(self, request):
        mobile =  CommonLib.filter_input(request.values.get('mobile'))
        otp =  CommonLib.filter_input(request.values.get('otp'))
        txn =  CommonLib.filter_input(request.values.get('txn'))
        try: 
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or len(mobile[0]) != 10:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            if otp[0] is None or len(otp[0]) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_130')}, 400
            if DEBUG_MODE and otp[0] != '123456':
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_131')}, 400
            if txn[0] is None or len(txn[0]) != 36:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_134')}, 400
           
            clientid = os.getenv('org_clientid')
            client_seret = os.getenv('org_client_secret')
            ts = str(int(time.time()))
            plain_text_key_created = client_seret + clientid + mobile[0] + otp[0]+ ts + txn[0]
            hmac = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            return {
                STATUS: SUCCESS,
                "post_data": {
                    'mobile': mobile[0],
                    'otp': otp[0],
                    'txn': txn[0],
                    'clientid': clientid,
                    'ts': ts,
                    'hmac': hmac
                    
                },
                "headers": {}
            }, 200
            
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_otp_v1:: ' + str(e)}, 400
        
    # To cehck the department and section limit
    def validate_limit_dept(self):
        count = 0
        for a in g.dept_details:
            if a:
                count += 1             
        return count  
    
    def validate_limit_section(self, dept_id):        
        count = 0     
        for key, value in g.sec_details.items(): 
            if value['dept_id'] == dept_id:
                count += 1   
        return count

    
    # To cehck the department and section limit
    def validate_name(self, name, type='dept'):
        # Convert the input name to lowercase
        name_lowercase = name.lower()
        
        # Determine the appropriate list based on the type
        if type == 'dept':
            # Assuming g.dept_details is accessible and contains department details
            details = g.dept_details
        else:
            # Assuming g.sec_details is accessible and contains section details
            details = g.sec_details

        names_list_lowercase = [detail.get('name','').lower() for a, detail in details.items() if detail.get('name') is not None]
        return name_lowercase in names_list_lowercase
        
    # To determine how many departments can be register with single user
    def find_departments_for_user(self, data, target_id):
        count = 0
        for entry in data:
            if entry.get('dept_id') == target_id and  not entry.get('sec_id'):
                count += 1
        return count   
      
    # To check the user count in department 
    def max_user_count_department(self, data, target_id):
        count = 0
        for entry in data:
            if entry.get('digilockerid') == target_id  and entry.get('dept_id') is not None and  not entry.get('sec_id') :
                count += 1
        return count
    
    # To determine how many sections can be register with single user
    def find_sections_for_user(self, data, digilockerid, dept_id):
        count = 0
        for entry in data:
            if entry.get('digilockerid') == digilockerid and entry.get('dept_id') == dept_id and entry.get('sec_id') is not None :
                count += 1
        return count 
        
        
    # To check the user count in department 
    def max_user_count_sections(self, data,  dept_id, sec_id):  
        count = 0      
        for entry in data:
            if entry.get('dept_id') == dept_id and entry.get('sec_id') == sec_id:
                count += 1
        return count
    
    @staticmethod    
    def log_exception(e):
    # Get the current stack and frame
        frame = inspect.currentframe()
        stack_trace = inspect.stack()[1]
        
        # Capture function name, file name, and line number
        function_name = stack_trace.function
        filename = stack_trace.filename
        line_number = stack_trace.lineno

        # Format the log data
        log_data = {
            'error_type': "Exception",
            'error': str(e),
            'traceback': traceback.format_exc(),
            'function': function_name,
            'filename': filename,
            'line_number': line_number,
            'time': datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'user': getattr(g, 'user', None),
            'endpoint': request.endpoint,
            'args': request.args.to_dict(),
            'form': request.form.to_dict(),
            'json': request.json if request.is_json else None,
            'transaction_id': getattr(g, 'transaction_id', 'N/A'),
            'ip_address': request.remote_addr
        }
        # Log the error
        logger.error(log_data)
                    
                    

