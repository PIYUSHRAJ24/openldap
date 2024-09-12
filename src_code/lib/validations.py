import inspect
import re
import ast
import traceback
import uuid
import json
import time
import hmac
import uuid
import hashlib
import requests
import xml.etree.ElementTree as ET
from flask import g
from thefuzz import fuzz
from lib.constants import *
from datetime import datetime
from lib.redislib import RedisLib
from lib.mongolib import MongoLib
from lib.commonlib import CommonLib
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
import logging
from pythonjsonlogger import jsonlogger


RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
logs_queue = 'org_logs_PROD'
logarray = {}
REDISLIB = RedisLib()
MONGOLIB = MongoLib()
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

    def isValidId(self, id):
        pattern = r'^[a-zA-Z0-9\-]{32}$'
        return re.fullmatch(pattern, id)
    
    def isValidPassword(self, id):
        pattern = r'^[a-zA-Z0-9]{10}$' 
        '''10 digit alphanumeric only--no any spcl char'''
        return re.fullmatch(pattern, id)  

    def is_valid_did(self, id):
        pattern = r'^[a-zA-Z0-9\-]{36}$'
        return re.fullmatch(pattern, id)
    
    def is_valid_access_id(self, id):
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
            except Exception :
                return

    def is_valid_pin(self, pin):
        pattern = r'^\d{6}$'
        return re.match(pattern, pin)

    def is_valid_pan(self, pan):
        pattern = r"^[A-Z]{5}\d{4}[A-Z]$"
        return re.match(pattern, pan)

    def is_valid_mobile(self, number):
        pattern = r"^\d{10}$"
        return re.match(pattern, str(number))
    
    def is_valid_email(self, email_id):
        pattern = r"^\S+@\S+\.\S+$"
        return re.match(pattern, email_id)
    
    def is_valid_cin(self, code):
        pattern = r"^([L|U]{1})(\d{5})([A-Za-z]{2})(\d{4})([A-Za-z]{3})(\d{6})$"
        return re.match(pattern, str(code))
    
    def is_valid_gstin(self, code):
        pattern = r"^\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$"
        return re.match(pattern, str(code))
    
    def is_valid_udyam(self, code):
        pattern = r"^UDYAM-[A-Z]{2}-\d{2}-\d{7}$"
        return re.match(pattern, str(code))

    def is_valid_date_elastic(self, date):
        if date is not None:
            try:
                datetime.datetime.strptime(date, "%Y-%m-%d")
                return True
            except Exception:
                return
            

    def is_valid_udyam_number(self, code, flag=False):
        if flag:
            query = {'udyam': code}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_196')}, 422 # type: ignore
        pattern = r"^UDYAM-[A-Z]{2}-\d{2}-\d{7}$"
        check = re.match(pattern, str(code))
        status = SUCCESS if check else ERROR
        code = 200 if check else 401
        return {STATUS: status, ERROR_DES: Errors.error('ERR_MSG_195')}, code


    def validate_string(self,name, string):
        if string == None or string == "":
            return 400, {'status': 'error', 'err_code': 128, 'msg': "%s is empty" % name}
        elif type(string) != type(""):
            return 400, {'status': 'error', 'err_code': 129, 'msg': "%s should be string not%s" % (name, str(type(string)))}
        elif name == "digilocker_id" and len(string) != 36:
            return 400, {'status': 'error', 'err_code': 130, 'msg': "%s should be 36 charecters in length%s" % (name, str(type(string)))}
        return 200, string
        
    def validate_org_info(self,data):
        filtered_data = {}
        digilockerid = data.get('digilocker_id')
        status, res = self.validate_string('digilockerid',digilockerid)
        if status == 400:
            return status, res
        filtered_data["digilocker_id"] = res

        din = data.get('din')
        status, res = self.validate_string('din',din)
        if status == 400:
            return status, res
        filtered_data["din"] = res
        
        is_active = data.get('is_active')
        status, res = self.validate_string('is_active',is_active)
        if status == 400:
            return status, res
        filtered_data["is_active"] = res

        filtered_data["added_on"] = datetime.datetime.now().strftime(D_FORMAT)
        
        deactivated_on = data.get('deactivated_on')
        if is_active == "N":
            status, res = self.validate_string('deactivated_on', deactivated_on)
            if status == 400:
                return status, res
            filtered_data["deactivated_on"] = res
        return 200, filtered_data

    def validate_org_info_list(self, data):
        if len(data) == 0:
            return 400, {'status': 'error', 'err_code': 128, 'msg': "dir_info is empty"}
        else:
            for value in data:
                status, res = self.validate_org_info(value)
                if status == 400:
                    return status, res
            return 200, data

    def validate_dict(self, data):
        if data != None and len(data) == 0:
            return 400, {'status': 'error', 'err_code': 128, 'msg': "dir_info is empty" }
        elif type(data) == type({}):
            return self.validate_org_info(data)
        elif type(data) == type([]):
            return self.validate_org_info_list(data)
        elif type(data) == type(''):
            try:
                data = json.loads(data)
                return self.validate_dict(data)
            except Exception:
                return 400, {'status': 'error', 'err_code': 128, 'msg': "Invalid format for dir_info" }
        else:
            return 200, None 

    def verify_name(self, request):
        name = CommonLib.filter_input(request.values.get('name'))
        original_name = CommonLib.filter_input(request.values.get("original_name"))
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

    def notifications(self, request):
        ''' Validate user details received over http request '''
        notification_id = CommonLib.filter_input(request.args.get('notification_id'))
        digilockerid = CommonLib.filter_input(request.args.get('digilockerid'))
        date_published = CommonLib.filter_date(request.args.get('date_published'))
        action_taken = CommonLib.filter_input(request.args.get('action_taken'))
        valid_thru = CommonLib.filter_date(request.args.get('valid_thru'))
        try:
            if notification_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "notification_id", RESPONSE: notification_id[0]}, 400
            elif notification_id[0] != None and self.isValidId(notification_id[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_103")}, 400
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None and self.is_valid_did(digilockerid[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if date_published[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date_published", RESPONSE: date_published[0]}, 400
            elif date_published[0] != None and self.is_valid_date(date_published[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_105")}, 400
            if valid_thru[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "valid_thru", RESPONSE: valid_thru[0]}, 400
            elif valid_thru[0] != None and self.is_valid_date(valid_thru[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_106")}, 400
            if action_taken[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "action_taken", RESPONSE: action_taken[0]}, 400
            elif action_taken[0] != None and action_taken[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_115")}, 400
            return {
                STATUS: SUCCESS,
                "notification_id": notification_id[0],
                "digilockerid": digilockerid[0],
                "date_published": date_published[0],
                "valid_thru": valid_thru[0],
                "action_taken": action_taken[0],
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:notifications::' + str(e)}, 400

    def notifications_model(self, request, operation):
        ''' Validate notification details received over http request '''
        notification_id = CommonLib.filter_input(request.values.get('notification_id'))
        digilockerid = CommonLib.filter_input(request.values.get('digilockerid'))
        date_published = CommonLib.filter_date(request.values.get('date_published'))
        valid_thru = CommonLib.filter_date(request.values.get('valid_thru'))
        message = CommonLib.filter_input(request.values.get('message'))
        date_read = CommonLib.filter_date(request.values.get('date_read'))
        action_taken = CommonLib.filter_input(request.values.get('action_taken'))
        is_valid = CommonLib.filter_input(request.values.get('is_valid'))
        try:
            if operation == 'C':
                data = {}
            elif notification_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "notification_id", RESPONSE: notification_id[0]}, 400
            elif notification_id[0] == None or self.isValidId(notification_id[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_103")}, 400
            else:
                data = {"notification_id": notification_id[0]}
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
                data["digilockerid"] = digilockerid[0]
            if date_published[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date_published", RESPONSE: date_published[0]}, 400
            elif date_published[0] != None:
                if  self.is_valid_date(date_published[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_105")}, 400
                data["date_published"] = date_published[0]
            if valid_thru[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "valid_thru", RESPONSE: valid_thru[0]}, 400
            elif valid_thru[0] != None:
                if self.is_valid_date(valid_thru[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_106")}, 400
                data["valid_thru"] = valid_thru[0]
            if message[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "message", RESPONSE: message[0]}, 400
            elif message[0] != None:
                data["message"] = message[0]
            if date_read[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date_read", RESPONSE: date_read[0]}, 400
            elif date_read[0] != None:
                if self.is_valid_date(date_read[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_113")}, 400
                data["date_read"] = date_read[0]
            if action_taken[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "action_taken", RESPONSE: action_taken[0]}, 400
            elif action_taken[0] != None:
                data["action_taken"] = action_taken[0]
            if is_valid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "is_valid", RESPONSE: is_valid[0]}, 400
            elif is_valid[0] != None:
                data["is_valid"] = is_valid[0]
            if len(data) == 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_114")}, 400
            return {STATUS: SUCCESS, "data": data}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:notifications_model::' + str(e)}, 400

    def public_notifications(self, request):
        ''' Validate public notifications details received over http request '''
        notification_id = CommonLib.filter_input(request.args.get('notification_id'))
        digilockerid = CommonLib.filter_input(request.args.get('digilockerid'))
        message_id = CommonLib.filter_input(request.args.get('message_id'))
        date_published = CommonLib.filter_date(request.args.get('date_published'))
        action_taken = CommonLib.filter_input(request.args.get('action_taken'))
        try:
            if notification_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "notification_id", RESPONSE: notification_id[0]}, 400
            elif notification_id[0] != None and self.isValidId(notification_id[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_103")}, 400
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None and self.is_valid_did(digilockerid[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if message_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "message_id", RESPONSE: message_id[0]}, 400
            elif message_id[0] != None and message_id[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_112")}, 400
            if date_published[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date_published", RESPONSE: date_published[0]}, 400
            elif date_published[0] != None and self.is_valid_date(date_published[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_105")}, 400
            if action_taken[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "action_taken", RESPONSE: action_taken[0]}, 400
            elif action_taken[0] != None and action_taken[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_115")}, 400
            return {
                STATUS: SUCCESS,
                "notification_id": notification_id[0],
                "digilockerid": digilockerid[0],
                "message_id": message_id[0],
                "action_taken": action_taken[0],
                "date_published": date_published[0],
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:public_notifications::' + str(e)}, 400

    def public_notifications_model(self, request, operation):
        ''' Validate public notifications details received over http request '''
        notification_id = CommonLib.filter_input(
            request.values.get('notification_id'))
        digilockerid = CommonLib.filter_input(
            request.values.get('digilockerid'))
        message_id = CommonLib.filter_input(request.values.get('message_id'))
        date_read = CommonLib.filter_date(request.values.get('date_read'))
        action_taken = CommonLib.filter_input(
            request.values.get('action_taken'))
        try:
            if operation == 'C':
                data = {}
            elif notification_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "notification_id", RESPONSE: notification_id[0]}, 400
            elif notification_id[0] == None or self.isValidId(notification_id[0]) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_103")}, 400
            else:
                data = {"notification_id": notification_id[0]}
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
                data["digilockerid"] = digilockerid[0]
            if message_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "message_id", RESPONSE: message_id[0]}, 400
            elif message_id[0] != None:
                if message_id[0] == '':
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_112")}, 400
                data["message_id"] = message_id[0]
            if date_read[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date_read", RESPONSE: date_read[0]}, 400
            elif date_read[0] != None:
                if self.is_valid_date(date_read[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_113")}, 400
                data["date_read"] = date_read[0]
            if action_taken[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "action_taken", RESPONSE: action_taken[0]}, 400
            elif action_taken[0] != None:
                data["action_taken"] = action_taken[0]
            if len(data) == 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_114")}, 400
            return {STATUS: SUCCESS, "data": data}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:public_notifications_model::' + str(e)}, 400

    def activity_insert(self, ac_type,subject,user):
        ''' Validate activity insert'''
        ac_type = CommonLib.filter_input(ac_type)
        subject = CommonLib.filter_input(subject)
        user = CommonLib.filter_input(user)
        try:
            if ac_type[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "type", RESPONSE: ac_type[0]}, 400
            elif ac_type[0] is None or ac_type[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_142")}, 400
            if subject[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "subject", RESPONSE: subject[0]}, 400
            elif subject[0] is None or subject[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_154")}, 400
            if user[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "user", RESPONSE: user[0]}, 400
            elif user[0] is None or not self.is_valid_did(user[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_119")}, 400
            
            post_data = {
                "user" : user[0],                
                "type" : ac_type[0],
                "subject" : subject[0]
            }
            return {STATUS: SUCCESS, "post_data": post_data}, 200
        
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::activity_insert:' + str(e)}, 400
    

    def authentication(self,user, request):
        ''' Validate hmac details received over http request '''
        user = CommonLib.filter_input(user)
        client_id = CommonLib.filter_input(request.values.get("client_id"))
        ts = CommonLib.filter_input(request.values.get("ts"))
        hmac = CommonLib.filter_input(request.values.get("hmac"))
        try:
            if user[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "user", RESPONSE: user[0]}, 400
            if client_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "client_id", RESPONSE: client_id[0]}, 400
            if ts[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "ts", RESPONSE: ts[0]}, 400
            if hmac[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "hmac", RESPONSE: hmac[0]}, 400
            elif hmac[1] < 10:
                return {STATUS: ERROR, ERROR_DES: "Invalid hmac"}, 400
            return {STATUS: SUCCESS, "user":user[0], "client_id": client_id[0], "ts": ts[0], "hmac": hmac[0]}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::authentication:' + str(e)}, 400
        
    def org_hmac(self, request):
        ''' Validate hmac details received over http request '''
        client_id = CommonLib.filter_input(request.headers.get('Clientid'))
        ts = CommonLib.filter_input(request.headers.get('Ts'))
        bearer = CommonLib.filter_input(request.headers.get('authorization', None))
        try:
            if client_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "Clientid", RESPONSE: client_id[0]}, 400
            elif client_id[0] == None or client_id[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_120")}, 400
            if ts[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "Ts", RESPONSE: ts[0]}, 400
            elif ts[0] == None or ts[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_121")}, 400
            if bearer[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "hmac", RESPONSE: bearer[0]}, 400
            elif bearer[0] == None or bearer[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_122")}, 400
            hmac_received = bearer[0].split(" ")[-1] if bearer is not None else None
            hash_key = CONFIG['organisation']['client_secret']
            hash_data = client_id[0] + ts[0]
            server_hmac = hmac.new(bytes(hash_key, 'latin-1'), hash_data.encode(), hashlib.sha256).hexdigest()
            if hmac_received != server_hmac:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_122")}, 400
            return {STATUS: SUCCESS, MESSAGE: 'Accepted'}
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:org_hmac:: ' + str(e)}, 400

    def validate_get_org_details(self, request):
        org_id = CommonLib.filter_input(request.values.get('org_id'))
        org_alias = CommonLib.filter_input(request.values.get('org_alias'))
        pan = CommonLib.filter_input(request.values.get('pan'))
        mobile = CommonLib.filter_input(request.values.get('mobile'))
        created_by = CommonLib.filter_input(request.values.get('created_by'))
        din = CommonLib.filter_input(request.values.get('din'))
        cin = CommonLib.filter_input(request.values.get('cin'))
        gstin = CommonLib.filter_input(request.values.get('gstin'))

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
            elif cin[0] != None and not self.is_valid_cin(cin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_148")}, 400
            elif cin[0] != None:
                filter_data["cin"] = cin[0]
            if gstin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "gstin", RESPONSE: gstin[0]}, 400
            elif gstin[0] != None and not self.is_valid_gstin(gstin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_150")}, 400
            elif gstin[0] != None:
                filter_data["gstin"] = gstin[0]
            return {
                STATUS: SUCCESS,
                "post_data": filter_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:validate_get_org_details:: ' + str(e)}, 500

    def get_org_details(self, request):
        ''' Validate org details received over http request '''

        keys = ["org_id", "org_alias", "pan", "created_by", "mobile", "din", "cin", "gstin"]
        res, status_code = self.validate_get_org_details(request)
        if status_code != 200:
            return res, status_code
        if True not in [res["post_data"].get(key) != None for key in keys]:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400
        return {STATUS: SUCCESS, 'post_data': res["post_data"]}, status_code

    def org_doc_count(self, request):
        ''' Validate org details received over http request '''
        res, status_code = self.org_hmac(request)
        if status_code == 400:
            return res, status_code
        org_id = CommonLib.filter_input(request.values.get('orgId'))
        date_read = CommonLib.filter_input(request.values.get('date'))
        try:   
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org_id", RESPONSE: org_id[0]}, 400
            elif org_id[0] == None or org_id[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            if date_read[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date", RESPONSE: date_read[0]}, 400
            elif date_read[0] != None:
                if self.is_valid_date_elastic(date_read[0]) is None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_113")+', format should be YYYY-MM-DD.'}, 400
            return {
                STATUS: SUCCESS,
                "org_id": org_id[0],
                "date": date_read[0]
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:org_doc_count:: ' + str(e)}, 400

    def org_details(self, request):
        ''' Validate org details received over http request '''
        org_id = CommonLib.filter_input(request.values.get('org_id'))
        org_alias = CommonLib.filter_input(request.values.get('org_alias'))
        
        try: 
            if not org_id[0] and not org_alias[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_125")}, 400  
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "orgId", RESPONSE: org_id[0]}, 400
            elif org_id[0] != None and org_id[0] == '':
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            if org_alias[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org_alias", RESPONSE: org_alias[0]}, 400
            elif org_alias[0] != None and not org_alias[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_124")}, 400
            
            post_data = {
                "org_id": org_id[0],
                "org_alias": org_alias[0],
            }
            return {
                STATUS: SUCCESS,
                "post_data":post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:org_doc_count:: ' + str(e)}, 400

    def hmac_authentication(self, request):
        ''' Validate hmac details received over http request '''
        
        client_id = CommonLib.filter_input(request.headers.get("clientid"))
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

    def hmac_authentication_sha3(self, request):
        ''' Validate hmac details received over http request '''
        
        client_id = CommonLib.filter_input(request.headers.get("clientid"))
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
            key_created = hashlib.sha3_256(plain_text_key_created.encode()).hexdigest()
            if hmac[0] == key_created:
                return {STATUS: SUCCESS, MESSAGE: 'Authenticated user found!'}, 200
            else:
                return{STATUS: ERROR, ERROR_DES: 'Unauthorised Access'}, 401

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::authenticationsha3:' + str(e)}, 400
        
    def validate_org_details(self, request):
        org_alias = CommonLib.filter_input(request.json.get('org_alias'))
        org_type = CommonLib.filter_input(request.json.get('org_type'))
        name = CommonLib.filter_input(request.json.get('name'))
        pan = CommonLib.filter_input(request.json.get('pan'))
        mobile = CommonLib.filter_input(request.json.get('mobile'))
        email = CommonLib.filter_input(request.json.get('email'))
        d_incorporation = CommonLib.filter_input(request.json.get('d_incorporation'))
        roc = CommonLib.filter_input(request.json.get('roc'))
        din = CommonLib.filter_input(request.json.get('din'))
        cin = CommonLib.filter_input(request.json.get('cin'))
        gstin = CommonLib.filter_input(request.json.get('gstin'))
        dir_info = request.json.get('dir_info')

        try:
            if org_alias[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org alias", RESPONSE: org_alias[0]}, 400
            elif org_alias[0] != None and not org_alias[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_124")}, 400
            if org_type[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org_type", RESPONSE: org_type[0]}, 400
            elif org_type[0] != None and not org_type[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_142")}, 400
            if name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name[0]}, 400
            elif name[0] != None and not name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_125")}, 400
            if pan[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "pan", RESPONSE: pan[0]}, 400
            elif pan[0] != None and not self.is_valid_pan(pan[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif mobile[0] != None and not self.is_valid_mobile(mobile[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if email[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "email", RESPONSE: email[0]}, 400
            elif email[0] != None and not self.is_valid_email(email[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_143")}, 400
            if d_incorporation[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "date of incorporation", RESPONSE: d_incorporation[0]}, 400
            elif d_incorporation[0] != None and not self.is_valid_date(d_incorporation[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_144")}, 400
            if roc[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "roc", RESPONSE: roc[0]}, 400
            elif roc[0] != None and not roc[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_163")}, 400
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: din[0]}, 400
            elif din[0] != None and len(din[0]) != 8:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_145")}, 400
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            elif cin[0] != None and not self.is_valid_cin(cin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_146")}, 400
            if gstin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "gstin", RESPONSE: gstin[0]}, 400
            elif gstin[0] != None and not self.is_valid_gstin(gstin[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            status, res = self.validate_dict(dir_info)
            if status == 400:
                return res, status
            dir_info = res

            post_data = {
                "org_alias": org_alias[0],
                "org_type": org_type[0],
                "name": name[0],
                "pan": pan[0],
                "mobile": mobile[0],
                "email": email[0],
                "d_incorporation": d_incorporation[0],
                "roc": roc[0],
                "din": din[0],
                "cin": cin[0],
                "gstin": gstin[0],
                "dir_info": dir_info,
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:validate_org_details:: ' + str(e)}, 500

    def update_org_details(self, request, org_id):
        '''  '''
        keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        res, status_code = self.validate_org_details(request)
        if status_code != 200:
            return res, status_code
        if org_id == None or not self.is_valid_did(org_id):
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
        res["post_data"]["org_id"] = org_id
        if True not in [res["post_data"].get(key) != None for key in keys]:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151") % str(keys)}, 400
        return res, status_code

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
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_145")}, 400
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
        
    def create_org_details(self, request):
        ''' Validate org details received over http request '''

        keys = ["org_id", "org_alias", "pan", "mobile", "cin", "gstin"]
        org_id = self.get_txn(CommonLib.filter_input(request.json.get('txn', ''))[0])
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

    def org_access_rules(self, request, operation = 'G'):
        ''' Validate org access rules received over http request '''
        digilockerid =  CommonLib.filter_input(request.values.get('digilockerid') or request.args.get('digilockerid'))
        access_id = CommonLib.filter_input(request.values.get('access_id') or request.args.get('access_id'))
        org_id = CommonLib.filter_input(request.values.get('org_id') or request.args.get('org_id'))
        cin =  CommonLib.filter_input(request.values.get('cin') or request.args.get('cin'))
        din =  CommonLib.filter_input(request.values.get('din') or request.args.get('din'))
        aadhaar =  CommonLib.filter_input(request.values.get('aadhaar') or request.args.get('aadhaar'))
        mobile = CommonLib.filter_input(request.values.get('mobile') or request.args.get('mobile'))
        email = CommonLib.filter_input(request.values.get('email') or request.args.get('email'))
        rule_id =  CommonLib.filter_input(request.values.get('rule_id') or request.args.get('rule_id'))
        designation =  CommonLib.filter_input(request.values.get('designation') or request.args.get('designation'))
        rule_name =  CommonLib.filter_input(request.values.get('rule_name') or request.args.get('rule_name'))
        updated_by = CommonLib.filter_input(request.values.get('updated_by') )
        # updated_on = datetime.datetime.now().strftime(D_FORMAT) #add this to worker
        is_active = CommonLib.filter_input(request.values.get('is_active'))
        dept_id = request.values.get('dept_id')
            
        try:   
            if not digilockerid[0] and not org_id[0] and not rule_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_126")}, 400
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None:
                if self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if org_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "org_id", RESPONSE: org_id[0]}, 400
            elif not org_id[0] or self.is_valid_did(org_id[0]) == None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            if rule_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "rule_id", RESPONSE: rule_id[0]}, 400
            elif rule_id[0] != None and not rule_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_127")}, 400
            if rule_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "rule_name", RESPONSE: rule_name[0]}, 400
            elif rule_name[0] != None and not rule_name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if access_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif access_id[0] != None and not access_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_141")}, 400
            
            # if dept_id[1] == 400:
            #     return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "dept_id", RESPONSE: dept_id[0]}, 400
            # elif dept_id == g.org_id:
            #     dept_id1= g.org_id
            # elif not dept_id[0] or self.is_valid_dept(dept_id[0]) == None:
            #     return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_207")}, 400

            if designation[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif not designation[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_162")}, 400
            if aadhaar[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "aadhaar", RESPONSE: aadhaar[0]}, 400
            elif operation == 'C2':
                if not aadhaar[0]:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
                aadhaar_dec = CommonLib.aes_decryption_v2(aadhaar[0], org_id[0][:16])
                if not aadhaar_dec or len(aadhaar_dec) != 12:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_138")}, 400
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif operation == 'C2' and mobile[0]:
                mobile_dec = CommonLib.aes_decryption_v2(mobile[0],org_id[0][:16])
                if mobile_dec and not self.is_valid_mobile(mobile_dec):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
                mobile = mobile_dec, 200 # type: ignore
            if email[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "email", RESPONSE: email[0]}, 400
            elif operation == 'C2':
                if not email[0]:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_143")}, 400
                email_dec = CommonLib.aes_decryption_v2(email[0],org_id[0][:16])
                if not email_dec or not self.is_valid_email(email_dec):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_143")}, 400
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: access_id[0]}, 400
            elif din[0] or (designation[0] == "director" and cin[0]):
                din_dec = CommonLib.aes_decryption_v2(din[0],org_id[0][:16]) 
                if not din_dec or len(din_dec) != 8:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_132")}, 400
                din = din_dec, 200 # type: ignore
            if is_active[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "is_active", RESPONSE: is_active[0]}, 400
            elif is_active[0] != None and not is_active[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_137")}, 400
            post_data = {
                'org_id': org_id[0],
                'digilockerid': digilockerid[0],
                'is_active': is_active[0] or "Y",
                'rule_id': rule_id[0],
                'rule_name': rule_name[0],
                'designation': designation[0],
                'updated_by': g.digilockerid
                # 'updated_on': updated_on,
            }
            if dept_id == g.org_id:
                post_data['dept_id'] = dept_id
                post_data['user_type'] = "default"
            else:
                post_data['dept_id'] = "" 

            if operation == 'C2':
                post_data['aadhaar'] = aadhaar_dec # type: ignore
                post_data['email'] = email_dec # type: ignore
                post_data['mobile'] = mobile[0] or None # type: ignore
                # Check if mobile, email or aadhaar of the user is already registered or requested.
                active_users = []
                for a in g.org_access_rules:
                    if a.get('is_active') == 'Y':
                        active_users.append({**CommonLib.get_profile_details(a), **Roles.rule_id(a.pop('rule_id'))})
    
                active_requests = []
                requests_res, status_code = MONGOLIB.org_eve("org_user_requests", {'org_id': g.org_id}, {}, limit = 1000)
                added_requests = []
                if status_code == 200 and len(requests_res[RESPONSE]) > 0:
                    for u in requests_res[RESPONSE]:
                        if u.get('request_status') == "initiated": # type: ignore
                            active_requests.append(u)
                        if u.get('request_status') == "created": # type: ignore
                            added_requests.append(u)

                if post_data['aadhaar']:
                    if len(added_requests) > 0 and post_data['aadhaar'] in [u.get('aadhaar') for u in added_requests]:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_209")}, 400
                    if len(active_requests) > 0 and post_data['aadhaar'] in [u.get('aadhaar') or None for u in active_requests]: # type: ignore
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_190")}, 400
                if post_data['email']:
                    if len(active_users) > 0 and post_data['email'] in [u.get('email') for u in active_users]:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_188")}, 400
                    if len(active_requests) > 0 and post_data['email'] in [u.get('email') or None for u in active_requests]: # type: ignore
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_189")}, 400
                if post_data['mobile']:
                    if len(active_users) > 0 and post_data['mobile'] in [u.get('mobile') for u in active_users]:
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_191")}, 400
                    if len(active_requests) > 0 and post_data['mobile'] in [u.get('mobile') or None for u in active_requests]: # type: ignore
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_187")}, 400

            if operation == 'C':
                post_data['access_id'] = hashlib.md5((org_id[0]+ digilockerid[0]).encode()).hexdigest() if not access_id[0] else access_id[0]
            return {
                STATUS: SUCCESS,
                "post_data": post_data,
                "din": din[0],
                "cin": cin[0]
            }, 200
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:org_access_rules:: ' + str(e)}, 400
                
        
    def transfer_access(self, request):
        ''' Validate org access rules received over http request '''
        digilockerid =  CommonLib.filter_input(request.values.get('digilockerid') or request.args.get('digilockerid'))
        
        try:
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif not digilockerid[0] or self.is_valid_did(digilockerid[0]) == None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            return {
                STATUS: SUCCESS,
                'digilockerid': digilockerid[0]
            }, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:transfer_access:: ' + str(e)}, 400

    def revoke_access(self, request):
        ''' Validate org access rules received over http request '''
        access_id = CommonLib.filter_input(request.values.get('access_id') or request.args.get('access_id'))
        # updated_on = datetime.datetime.now().strftime(D_FORMAT) # add this to worker
        
        try:
            access_id_1 = CommonLib.aes_decryption_v2(access_id[0], g.org_id[:16])
            
            if access_id_1 is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_210")}, 400
            elif access_id_1 and not self.is_valid_access_id(access_id_1):
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_141")}, 400
            
            for a in g.org_access_rules:
                if a.get('access_id') == access_id_1 and a.get('is_active') == "N":
                   return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_212")}, 400 
            
            post_data = {
                'access_id': access_id_1,
                # 'updated_on': updated_on,
                'is_active': "N"
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:revoke_access:: ' + str(e)}, 400

    def grant_access(self, request):
        ''' Validate org access rules received over http request '''
        digilockerid =  CommonLib.filter_input(request.values.get('digilockerid') or request.args.get('digilockerid'))
        access_id = CommonLib.filter_input(request.values.get('access_id') or request.args.get('access_id'))
        rule_name =  CommonLib.filter_input(request.values.get('rule_name') or request.args.get('rule_name'))
        # updated_on = datetime.datetime.now().strftime(D_FORMAT) # add this to worker
        
        try:
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None and self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if access_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif access_id[0] != None and not access_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_141")}, 400
            if not (digilockerid[0] or access_id[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_126")}, 400
            if rule_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "rule_name", RESPONSE: rule_name[0]}, 400
            elif rule_name[0] != None and not rule_name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            post_data = {
                'digilockerid': digilockerid[0],
                'access_id': access_id[0],
                'rule_name': rule_name[0],
                # 'updated_on': updated_on,
                'is_active': "Y"
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data
            }, 200
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:grant_access:: ' + str(e)}, 400

    def assign_access(self, request):
        ''' Validate org access rules received over http request '''
        digilockerid =  CommonLib.filter_input(request.values.get('digilockerid') or request.args.get('digilockerid'))
        access_id = CommonLib.filter_input(request.values.get('access_id') or request.args.get('access_id'))
        rule_name =  CommonLib.filter_input(request.values.get('rule_name') or request.args.get('rule_name'))
        designation =  CommonLib.filter_input(request.values.get('designation') or request.args.get('designation'))
        cin =  CommonLib.filter_input(request.values.get('cin') or request.args.get('cin'))
        din =  CommonLib.filter_input(request.values.get('din') or request.args.get('din'))
        # updated_on = datetime.datetime.now().strftime(D_FORMAT) # add this to worker
        
        try:
            if digilockerid[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "digilockerid", RESPONSE: digilockerid[0]}, 400
            elif digilockerid[0] != None and self.is_valid_did(digilockerid[0]) == None:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_104")}, 400
            if access_id[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif access_id[0] != None and not access_id[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_141")}, 400 
            if not (digilockerid[0] or access_id[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_126")}, 400       
            if designation[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "access_id", RESPONSE: access_id[0]}, 400
            elif designation[0] != None and not designation[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_162")}, 400
            if rule_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "rule_name", RESPONSE: rule_name[0]}, 400
            elif rule_name[0] != None and not rule_name[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_136")}, 400
            if cin[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "cin", RESPONSE: cin[0]}, 400
            if din[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "din", RESPONSE: access_id[0]}, 400
            elif designation[0] == "director":
                if not din[0] or len(din[0]) != 8:
                    return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_145")}, 400
                # if not cin[0] and not self.is_valid_cin(cin[0]):
                #     return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_146")}, 400
                # res, status_code = self.director_name_match(cin[0], din[0], digilockerid[0])
                # if status_code != 200:
                #     return res, status_code
            post_data = {
                'digilockerid': digilockerid[0],
                'access_id': access_id[0],
                'rule_name': rule_name[0],
                'designation': designation[0],
                # 'updated_on': updated_on,
                'is_active': "Y"
            }
            return {
                STATUS: SUCCESS,
                "post_data": post_data,
                "din": din[0]
            }, 200
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:grant_access:: ' + str(e)}, 400

    def upload_file_validation(self, request):
        try:
            if len(request.files) == 0:
                return 404, {"status": "error", "error_description": "File not found."}
          
            file = request.files['body']  # Requesting file from multi/form-data
            
            # file_bytes = np.fromfile(file, np.uint8)
            # file = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            allowed_extensions = ('jpg','png', 'jpeg')
            file_name = CommonLib.filter_input_file_upload(file.filename).replace(' ','')
            file_ext_split = file_name.split('.')
            file_ext = file_ext_split[-1].lower()
            if file_ext not in allowed_extensions:
                return 400, {"status": "error", "error_description": "Allowed File Types are JPG, JPEF and PNG."}

            
            file_name = 'avataar.jpg' 
            
            # file_content = file.read()
            # decodeit = open(file_name, 'wb')
            # decodeit.write(file_content)
            # decodeit.close()
            # im = Image.open(file_name)
            # rgb_im = im.convert('RGB')
            # resize = rgb_im.resize((int(1024),int(1024)))
            
            # print(type(resize))
            
            # pil_im = Image.fromarray(resize)
            # b = io.BytesIO()
            # pil_im.save(b, 'jpeg')
            # im_bytes = b.getvalue()
            file.seek(0, os.SEEK_END)            
            file_length = file.tell()
            
            if file_length > 0.09765625 * (1024 * 1024):  # Validating file size 100kb i.e, 0.09765625 mb
           
                return 400, {f"status": "error",
                             "error_description": f"Max upload size - 100 KB."}
            file.seek(0, 0) #add this line otherwise file will be empty
            return 200, [file_name, file]

        except Exception as e:
            return 400, {'status': 'error', 'error_description': 'Exception:Validations:upload_file_validation::' + str(e)} 

   
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

    def valid_txn(self, txn):
        try:
            redis_txn = REDISLIB.get(txn + '_logID')
            if txn == redis_txn:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False

    def send_otp(self, request, org_id):
        try:
            uid = request.values.get('uid')
            din = request.values.get('din')
            uid_decrypted = CommonLib.aes_decryption_v2(uid, org_id[:16])
            if uid_decrypted is None or len(uid_decrypted) != 12:
                return {STATUS: ERROR,  ERROR_DES: Errors.error('ERR_MSG_138')}, 400
            din_decrypted = CommonLib.aes_decryption_v2(din, org_id[:16])
            if din_decrypted != None and len(din_decrypted) != 8:
                return {STATUS: ERROR,  ERROR_DES: Errors.error('ERR_MSG_132')}, 400
            return [uid_decrypted, din_decrypted], 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: 'Exception:Validations:send_OTP_valid::' + str(e)}, 400

    def verify_otp(self, request, org_id):
        try:
           
            uid = CommonLib.filter_input(request.values.get('uid'))
            uid_decrypted = CommonLib.aes_decryption_v2(uid[0],org_id[:16])
            txn = CommonLib.filter_input(request.values.get("txn"))
            otp = CommonLib.filter_input(request.values.get('otp'))
            otp_decrypted = CommonLib.aes_decryption_v2(otp[0],org_id[:16])
            consent = CommonLib.filter_input(request.values.get("consent"))
            
            # todo validation rules
            if otp_decrypted is None or len(otp_decrypted) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_130')}, 400
            if uid_decrypted is None or len(uid_decrypted) != 12:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_138')}, 400
            if consent[0] is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_139')}, 400
            if txn[0] is None or len(txn[0]) != 36:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_134')}, 400
            elif not self.valid_txn(txn[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_140')}, 400
            return [uid_decrypted, txn[0], otp_decrypted, consent[0]], 200
        except Exception as e:
            return 400, {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_OTP_valid::' + str(e)}


    def send_otp_v1(self, request, org_id):
        try:
            mobile_decrypted = CommonLib.aes_decryption_v2(request.values.get('mobile'), org_id[:16])
            if mobile_decrypted is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile decryption failed"}, 400

            mobile = CommonLib.filter_input(mobile_decrypted)
            if mobile is None or mobile[0] is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile filtering failed"}, 400

            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or len(mobile[0]) != 10:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            
            clientid = os.getenv('org_clientid')
            client_seret = os.getenv('org_client_secret')

            if not clientid or not client_seret:
                return {STATUS: ERROR, ERROR_DES: 'Missing client credentials'}, 400

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

    
    def verify_otp_v1(self, request,org_id):
        mobile_decrypted = CommonLib.aes_decryption_v2(request.values.get('mobile'), org_id[:16])
        if mobile_decrypted is None:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile decryption failed"}, 400
        mobile = CommonLib.filter_input(mobile_decrypted)
        if mobile is None or mobile[0] is None:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile filtering failed"}, 400
          
        otp_decrypted = CommonLib.aes_decryption_v2(request.values.get('otp'), org_id[:16])
        if otp_decrypted is None:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_130") % "otp decryption failed"}, 400
        otp = CommonLib.filter_input(otp_decrypted)
        if otp is None or otp[0] is None:
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_130") % "otp filtering failed"}, 400
        
        txn =  CommonLib.filter_input(request.values.get('txn'))
        try: 
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or len(mobile[0]) != 10:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            if otp[0] is None or len(otp[0]) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_130')}, 400
            # if DEBUG_MODE and otp[0] != '123456':
            #     return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_131')}, 400
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
        
    def send_email_otp(self,request,org_id = None):
        email = CommonLib.filter_input(request.values.get('email'))
        email_decrypted = CommonLib.aes_decryption_v2(email[0],org_id[:16])
        try:
            if email_decrypted == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "email", RESPONSE: email_decrypted}, 400
            elif email_decrypted != None and not self.is_valid_email(email_decrypted):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_143")}, 400
            return {STATUS: SUCCESS,"email": email_decrypted}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:send_email_otp::' + str(e)},400

    def verify_email_otp(self,request,org_id =None):
        otp = CommonLib.filter_input(request.values.get('otp'))
        txn = CommonLib.filter_input(request.values.get('txn'))
        otp_decrypted = CommonLib.aes_decryption_v2(otp[0],org_id[:16])
        try:
            if otp_decrypted == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "otp", RESPONSE: otp_decrypted}, 400
            elif not otp_decrypted and len(otp_decrypted) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_130")}, 400
            if txn[0] is None or len(txn[0]) != 36:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_134')}, 400
            return {STATUS: SUCCESS,"otp": otp_decrypted,"txn":txn[0]}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:verify_email_otp::' + str(e)},400
            
    def tags_validation(self, request):
        try:
            ""
        except Exception:
            ""

    def file_lock(self,request, secret):
        enc_password = request.values.get("user_password")
        try:
            password = CommonLib.aes_decryption_v2(enc_password, secret)
            if password is None or self.isValidPassword(password) is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_151")}, 400

            return password, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:file_lock::' + str(e)}, 400
        
    def user_location(self, request):
        try:
            request_data = request.get_json()
            browser_name = request_data.get('login_history').get('browser')
            lat = request_data.get('login_history').get("lat")
            lon = request_data.get('login_history').get('lon')
            lockerid = request_data.get("lockerid")
            public_ip = request_data.get('login_history').get("public_ip")
            server_ip = request_data.get('login_history').get("server_ip")
            if browser_name is None :
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_170')}, 400
            if lat is None :
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_171')}, 400
            if lon is None:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_172')}, 400
            if lockerid is None or len(lockerid) != 36:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_167')}, 400
            if public_ip is None :
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_169')}, 400
            if server_ip is None :
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_168')}, 400
            
            return [browser_name, lat, lon,lockerid,public_ip,server_ip], 200
        except Exception as e:
            return 400, {STATUS: ERROR, ERROR_DES: 'Exception:Validations:user_location::' + str(e)}

    def is_valid_cin_v2(self, request, org_id):
        ''' check valid CIN'''
        try:
            cin_no = CommonLib.filter_input(request.values.get('cin'))
            cin_name = CommonLib.filter_input(request.values.get('cin_name'))
            cin_decrypted = CommonLib.aes_decryption_v2(cin_no[0], org_id[:16])
            name_decrypted = CommonLib.aes_decryption_v2(cin_name[0], org_id[:16])
            cin = cin_decrypted if cin_decrypted is not None else cin_no
            name = name_decrypted if name_decrypted is not None else cin_name
            if not cin or not self.is_valid_cin(cin):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_146")}, 400
            if not name :
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
            query = {'ccin': cin}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_182')}, 406
            else:
                return {STATUS: SUCCESS, 'cin': cin, 'name': name}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_cin_v2:' + str(e)}, 400

    def is_valid_cin_v3(self, request, org_id):
        ''' check valid CIN HMAC based '''
        try:
            input_data_raw = request.get_data().decode("utf-8")
            input_data = json.loads(input_data_raw)
            cin_no = input_data.get("cin")
            cin_name = input_data.get("cin_name")
            cin_decrypted = CommonLib.aes_decryption_v2(cin_no, org_id[:16])
            name_decrypted = CommonLib.aes_decryption_v2(cin_name, org_id[:16])
            cin = cin_decrypted if cin_decrypted is not None else cin_no
            name = name_decrypted if name_decrypted is not None else cin_name
            print("cin",cin)
            print("cin_name",name)
            if not cin or not self.is_valid_cin(cin):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_146")}, 400
            if not name :
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_199")}, 400
            query = {'ccin': cin}
            print("Is it called HEREEE", query)
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            if status_code == 200 and len(res[RESPONSE]) > 0:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_182')}, 406
            else:
                return {STATUS: SUCCESS, 'cin': cin, 'name': name}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_cin_v3:' + str(e)}, 400

    def is_valid_gstin_v2(self, request, org_id):
        try: 
            input_data_raw = request.get_data().decode("utf-8")
            input_data = json.loads(input_data_raw)
            gstin_enc = input_data.get("gstin")
            name_enc = input_data.get("name")
            gstin_decrypted = CommonLib.aes_decryption_v2(gstin_enc, org_id[:16])
            name_decrypted = CommonLib.aes_decryption_v2(name_enc, org_id[:16])
            gstin = gstin_decrypted if gstin_decrypted is not None else gstin_enc
            name = name_decrypted if name_decrypted is not None else name_enc
            if not gstin or not self.is_valid_gstin(gstin):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
            if not name :
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_147")}, 400
           
            query = {'gstin': gstin}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)
            
            if status_code == 200 and len(res[RESPONSE]) > 0:
                log_data = {RESPONSE: 'GSTIN is already associated with the organization.'}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_gstin')
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_208')}, 406
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

    
    def verify_name_v3(self, name, original_name):
        try:
            if name == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "name", RESPONSE: name}, 400
            elif name is None or name == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_101")}, 400
            if original_name == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "original_name", RESPONSE: original_name}, 400
            elif original_name is None or original_name == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_102")}, 400
            return {STATUS: SUCCESS, "name": name, "original_name": original_name}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::verify_name:' + str(e)}, 400

    def is_valid_icai(self, request, org_id):
        try:
            icai_enc = request.values.get('icai')
            icai = CommonLib.aes_decryption_v2(icai_enc, org_id[:16])
            if not icai or len(icai) != 6:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_184")}, 400

            pattern = r"^\d{6}$"
            check = re.match(pattern, str(icai))
            if check:
                query = {'icai': icai}
                res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)

                if status_code == 200 and len(res[RESPONSE]) > 0:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_186')}, 406
                else:
                    return {STATUS: SUCCESS, 'icai': icai}, 200
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_184')}, 400
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_icai:' + str(e)}, 400
        
    def esign_consent_val(self, request):
        try:
            doc_name = CommonLib.filter_input(request.values.get('doc_name'))
            if doc_name[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193") % "doc_name", RESPONSE: doc_name[0]}, 400
            elif doc_name[0] is None or doc_name[0] == "":
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_193")}, 400
            
            return {STATUS: SUCCESS, "doc_name": doc_name[0]}, 200

        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations::is_valid_icai:' + str(e)}, 400    
    
    # get_udcer function not in use for entity_auth component from 9 Aug 2024
    def get_udcer(self, request, org_id):
        
        input_data_raw = request.get_data().decode("utf-8")
        input_data = json.loads(input_data_raw)

        udyam_number = input_data.get("udyam_number")
        mobile = input_data.get("mobile")

        mobile_decrypted = CommonLib.filter_input(CommonLib.aes_decryption_v2(mobile, org_id[:16]))
        udyam_number_decrypted = CommonLib.filter_input(CommonLib.aes_decryption_v2(udyam_number, org_id[:16]))
        
  
        mobile = mobile_decrypted if mobile_decrypted is not None else mobile
        udyam_number = udyam_number_decrypted if udyam_number_decrypted is not None else udyam_number
        
        
        
        try:
            if mobile[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile[0] or not self.is_valid_mobile(mobile[0]):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            if udyam_number[1] == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "udyam_number", RESPONSE: udyam_number[0]}, 400
            elif not udyam_number[0]:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_195")}, 400
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
    
    def is_valid_udyam_v2(self, request, org_id):
        
        input_data_raw = request.get_data().decode("utf-8")
        input_data = json.loads(input_data_raw)
        
        udyam_number_encrypted = input_data.get("udyam_number")
        mobile_encrypted = input_data.get("mobile")
        
        mobile_decryption_result = CommonLib.filter_input(CommonLib.aes_decryption_v2(mobile_encrypted, org_id[:16]))
        udyam_number_decryption_result = CommonLib.filter_input(CommonLib.aes_decryption_v2(udyam_number_encrypted, org_id[:16]))

        # Handle tuple returns from decryption
        mobile = mobile_decryption_result[0] if mobile_decryption_result[0] is not None else mobile_encrypted
        udyam_number = udyam_number_decryption_result[0] if udyam_number_decryption_result[0] is not None else udyam_number_encrypted

        try:
            if mobile == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "mobile", RESPONSE: mobile[0]}, 400
            elif not mobile or not self.is_valid_mobile(mobile):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_149")}, 400
            if udyam_number == 400:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_100") % "udyam_number", RESPONSE: udyam_number[0]}, 400
            elif not udyam_number or not self.is_valid_udyam(udyam_number):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_195")}, 400

            query = {'udyam': udyam_number}
            res, status_code = MONGOLIB.org_eve(CONFIG["org_eve"]["collection_details"], query, {}, limit=500)          

            if status_code == 200:
                log_data = {RESPONSE: 'UDYAM is already associated with the organization.'}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'update_gstin')
                return res, status_code
            else:
                log_data = {RESPONSE: 'Udyam number and mobile successfully decrypted'}
                logarray.update(log_data)
                RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'set_gstin')
                return {STATUS: SUCCESS, 'mobile': mobile ,'udyam_number': udyam_number}, 200

        except Exception as e:
            log_data = {RESPONSE: e}
            logarray.update(log_data)
            RABBITMQ_LOGSTASH.log_stash_logeer(logarray, logs_queue, 'update_gstin')
            return {STATUS: ERROR, ERROR_DES: 'Exception:Validations:get_udcer:: ' + str(e)}, 400
      

    def is_valid_udcer(self, request,org_id):
        res, status_code = self.get_udcer(request,org_id)
        if status_code != 200:
            return res, status_code

        url = CONFIG['msme']['udcer_url']
        headers = {
            'X-APISETU-APIKEY': CONFIG['mca']['api_key'],
            'X-APISETU-CLIENTID': CONFIG['mca']['client_id'],
            'accept': 'application/xml',
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url=url, headers=headers, data=json.dumps(res['post_data']))
        if response.status_code >= 500 and response.status_code < 600:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_155'), RESPONSE: response.content}, response.status_code
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
            data['udyam'] = res['post_data']['certificateParameters']['udyamNumber']
            data['enterprise_name'] = response_xml.find('.//Unit1').get('name') # type: ignore
            data['phone'] = response_xml.find(enterprise).get('phone') # type: ignore
            data['email'] = response_xml.find(enterprise).get('email') # type: ignore
            data['date_of_incorporation'] = doi
            return {STATUS: SUCCESS, RESPONSE: data}, 200
        else:
            res = json.loads(response.content)
            return {STATUS: ERROR, ERROR_DES: res.get('errorDescription') or Errors.error('ERR_MSG_155'), RESPONSE: res.get('error') or res}, response.status_code
    

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
            'error': str(e),
            'traceback': traceback.format_exc(),
            'function': function_name,
            'filename': filename,
            'line_number': line_number,
            'time': datetime.utcnow().isoformat()
        }
        # Log the error
        logger.error(log_data)
            