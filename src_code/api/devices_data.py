import os
from dotenv import load_dotenv
from flask import request, Blueprint, json, g, Response, jsonify
from lib.authenticator import ValidateUser
from lib.redislib import RedisLib
from lib.rabbitmq import RabbitMQ
from lib.constants import ERROR, ERROR_DES, STATUS, RESPONSE, SUCCESS
from lib.utils import DeviceUtils, PostData, load_credential
from lib.constants import CONFIG

load_dotenv()
bp= Blueprint("devices_data", __name__)
status_code= 200
redilib= RedisLib()

logarray = {}
logs_mq = RabbitMQ()
logs_queue_name= "acsapi_devices_logs_"

load_credential()

@bp.after_request
def add_header(response) :
    ''' add header'''
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Permissions-Policy"] = "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()"
    return response

@bp.before_request
def before_request():
    ''' before requests'''    
    try:
        if request.method== os.getenv("METHOD_OPTIONS"):
            return json.dumps({STATUS: ERROR, ERROR_DES: "OPTIONS_OK"})
        bypass_urls = ("healthcheck")
        if request.path.split('/')[1] in bypass_urls:
            return
        jwt_lib= ValidateUser(request=request)
        if os.getenv("AUTH_MODE")== "OAUTH":
            g.digilocker_id = request.headers.get("digilockerid", request.headers.get("Digilockerid", None))
            g.partner_id = request.headers.get("partner_id", request.headers.get("Partner_id", request.headers.get("Partner-Id", None)))
            g.client_id = request.headers.get("clientid", request.headers.get("Clientid", None))
            g.ts = request.headers.get("ts", request.headers.get("Ts", None))
            g.key_hash = request.headers.get("hmac", request.headers.get("Hmac", None))
            status_code, jwt_res= jwt_lib.check_auth()
            if status_code==200 and jwt_res is not None:
                g.user_data= jwt_res
                logarray.update({"digilockerid": g.digilocker_id, "partner_id": g.partner_id})
            else:
                return jwt_res, status_code
        else:
            status_code, jwt_res= jwt_lib.check_auth()
            if status_code==200 and jwt_res is not None:
                g.jwt_token= jwt_lib.token
                g.device_id= jwt_lib.device_security_id
                g.user_data= jwt_res
                logarray.update({"digilockerid": g.user_data.get("locker_id"), "device_id": g.device_id})
            else:
                return jwt_res, status_code
    except Exception as e:
        return Response(json.dumps({STATUS:ERROR, ERROR_DES: "Exception(JWT):" + str(e)}), status=401, content_type=os.getenv("APPLICATION_JSON"))

# digiLocker device registration, listing and 
# sending notification code written below
@bp.route(rule="v1/list", methods=["GET"])
def get_all_details_by_locker_id():
    ''' get all details by locker id '''
    try:
        #Get the json payload from the request
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        locker_id= payload.get("user_id", "")
        
        if locker_id is None or locker_id== "" :
            error_msg=json.dumps({STATUS:ERROR, ERROR_DES: "Plz provide the User ID."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_locker_id(locker_id= locker_id)         
        response= json.dumps(db_response)
        return Response(response, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
    except Exception as e:
        error_msg=json.dumps({STATUS: ERROR,  ERROR_DES: str(e)})
        return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
    
@bp.route(rule="v1/save", methods=["POST"])
def insert_devices_data():
    ''' insert method '''
    try:
        #Get the json payload from the request
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        locker_id= payload.get("digilockerid", "")
        device_id= payload.get("device_id", "")
        fcm_token= payload.get("fcm_token", "")
        
        if locker_id and locker_id== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the DigiLocker id in payload"}), 400
        elif device_id and device_id== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the Device id in payload"}), 400
        elif fcm_token and fcm_token== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the FCM token in payload"}), 400        
        device_utils= DeviceUtils()
        db_res, status_code= device_utils.find_devices_by_locker_id(locker_id)
        count_data=0        
        if db_res is not None and status_code== 200:            
            count_data= len(db_res["response"])        
        redis_key="devices_"+locker_id
        if count_data== 0:
            device_utils.send_devices_data_to_queue("C", payload)
            return jsonify({STATUS:SUCCESS, "message": "Saved."}), 200
        elif count_data > 0 and count_data < 3:
            exist= device_utils.is_data_exist(db_res, device_id)            
            redis_res= redilib.get(redis_key)
            if redis_res is not None:
                redilib.remove(redis_key)
            if exist:
                device_utils.send_devices_data_to_queue("U", payload)
                message= "Updated."
            else:
                device_utils.send_devices_data_to_queue("C", payload)
                message= "Saved."
            return jsonify({STATUS:SUCCESS, "message": message}), 200
        else:
            exist= device_utils.is_data_exist(db_res, device_id)            
            redis_res= redilib.get(redis_key)
            if redis_res is not None:
                redilib.remove(redis_key)
            if exist:
                device_utils.send_devices_data_to_queue("U", payload)
                return jsonify({STATUS:SUCCESS, "message": "Updated."}), 200
            else:
                device_utils.send_devices_data_to_queue("DU", payload)
                return jsonify({STATUS:SUCCESS, "message": "Saved."}), 200
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:str(e)}), 400
    
@bp.route(rule="v1/send/notification", methods=["POST"])
def send_notification_to_mobile_by_fcm():
    try:        
        #Get the json payload from the request find user_id notification title and body and action type
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))                        
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        user_id= payload.get("user_id", "")
        title= payload.get("title", "")        
        body= payload.get("body", "")
        image= payload.get("image", "")
        action= payload.get("action", "")        
        priority= payload.get("priority", "")
        
        if user_id is None or user_id == "":
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Invalid userid."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_locker_id(locker_id= user_id)
        
        if status_code== 200:
            reg_id_list=[]#fcm token load here
            for row in db_response["response"]:
                reg_id_list.append(row["fcm_token"])
            
            dict_payload= {
                "registration_ids": reg_id_list, 
                "priority": priority, 
                "notification": {
                    "title": title,
                    "body": body,
                    "image": image
                },
                "data": {
                    "title": title,
                    "body": body,
                    "actionType": action,
                    "image": image
                }
            }            
            if action is not None and (action== "webview" or action== "browser"):
                url= payload.get("url", "")    
                web_page_title= payload.get("web_title", "")            
                main_payload= {
                    action: { 
                        "title": web_page_title, 
                        "url": url
                    }
                }                
            elif action is not None and action== "dialog" :
                url= payload.get("url", "")    
                dialog_messgae= payload.get("message", "")    
                dialog_title= payload.get("title", "")            
                main_payload= {
                    action: { 
                        "title": dialog_title, 
                        "message": dialog_messgae,
                        "image": url
                    }
                }
            elif action is not None and action== "store" :
                android_url= payload.get("playstore_url", "")    
                appstore_url= payload.get("appstore_url", "")    
                main_payload= {
                    action: { 
                        "playStoreUrl": android_url, 
                        "appStoreUrl": appstore_url
                    }
                }
            dict_payload["data"].update(main_payload)
            json_payload=json.dumps(dict_payload)
            firebase_config= CONFIG["firebase_config"]
            headers={os.getenv("CONTENT_TYPE"): "application/json", "Authorization":"key="+firebase_config["fcm_auth_key"]}
            post_data= PostData(firebase_config["push_notificatetion_url"], header=headers, payload=json_payload)
            server_res= post_data.send_post_request()
            if server_res.status_code== 200:
                return json.loads(server_res.text)
            return jsonify({STATUS: ERROR,  ERROR_DES:"Unable to send firebase notification." + str(e)}), 400                    
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:"Excption in sending notification:::" + str(e)}), 400
    
# entity locker device registration, listing and 
# sending notification code written below
@bp.route(rule="v1/save/entity", methods=["POST"])
def insert_entity_devices_data():
    ''' insert method '''
    try:
        #Get the json payload from the request
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        locker_id= payload.get("digilockerid", "")
        device_id= payload.get("device_id", "")
        fcm_token= payload.get("fcm_token", "")
        entity_id= payload.get("entity_id", "")        
        
        if entity_id and entity_id== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the Organisation id in payload"}), 400
        elif locker_id and locker_id== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the DigiLocker id in payload"}), 400
        elif device_id and device_id== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the Device id in payload"}), 400
        elif fcm_token and fcm_token== "" :
            return jsonify({STATUS:ERROR, ERROR_DES: "Plz provide the FCM token in payload"}), 400        
        dev_utils= DeviceUtils()
        db_res, status_code= dev_utils.find_devices_by_locker_id_and_entity_id(locker_id= locker_id, entity_id= entity_id)
        count_data=0                
        if db_res is not None and status_code== 200:
            count_data= len(db_res["response"])
        redis_key="devices_"+locker_id+"_"+entity_id
        redis_key_by_entity="devices_"+entity_id        
        if count_data== 0:
            dev_utils.send_entity_devices_data_to_queue(operation="C", data= payload)
            return jsonify({STATUS:SUCCESS, "message": "Saved."}), 200
        elif count_data > 0 and count_data < 3:
            exist= dev_utils.is_data_exist(db_res, device_id)            
            redis_res= redilib.get(redis_key)
            redis_res_by_entity= redilib.get(redis_key_by_entity)            
            
            if redis_res_by_entity is not None:
                redilib.remove(redis_key_by_entity)
            
            if redis_res is not None:
                redilib.remove(redis_key)
            
            if exist:
                dev_utils.send_entity_devices_data_to_queue(operation= "U", data= payload)
                message= "Updated."
            else:
                dev_utils.send_entity_devices_data_to_queue(operation= "C", data= payload)
                message= "Saved."
            return jsonify({STATUS:SUCCESS, "message": message}), 200
        else:
            exist= dev_utils.is_data_exist(db_res, device_id)            
            redis_res= redilib.get(redis_key)
            redis_res_by_entity= redilib.get(redis_key_by_entity)
            
            if redis_res_by_entity is not None:
                redilib.remove(redis_key_by_entity)
                
            if redis_res is not None:
                redilib.remove(redis_key)
            
            if exist:
                dev_utils.send_entity_devices_data_to_queue(operation= "U", data= payload)
                return jsonify({STATUS:SUCCESS, "message": "Updated."}), 200
            else:
                dev_utils.send_entity_devices_data_to_queue(operation= "DU", data= payload)
                return jsonify({STATUS:SUCCESS, "message": "Saved."}), 200
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:str(e)}), 400

@bp.route(rule="v1/list/entity/self", methods=["GET"])
def get_all_details_of_entity_by_locker_id():
    ''' get all details by locker id '''
    try:
        #Get the json payload from the request
        payload= request.get_json()
        if not payload:            
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        locker_id= payload.get("user_id", "")
        entity_id= payload.get("entity_id", "")
        if locker_id is None or locker_id== "" :
            error_msg=json.dumps({STATUS:ERROR, ERROR_DES: "Plz provide the User ID."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        
        if entity_id is None or entity_id== "" :
            error_msg=json.dumps({STATUS:ERROR, ERROR_DES: "Plz provide the Organization ID."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_locker_id_and_entity_id(locker_id= locker_id, entity_id=entity_id) 
        response= json.dumps(db_response)
        return Response(response, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
    except Exception as e:
        error_msg=json.dumps({STATUS: ERROR,  ERROR_DES: str(e)})
        return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            

@bp.route(rule="v1/list/entity/alluser", methods=["GET"])
def get_all_details_by_entity_id():
    ''' get all details by locker id '''
    try:
        #Get the json payload from the request
        payload= request.get_json()
        if not payload:            
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        
        entity_id= payload.get("entity_id", "")        
        if entity_id is None or entity_id== "" :
            error_msg=json.dumps({STATUS:ERROR, ERROR_DES: "Plz provide the Organization ID."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_entity_id(entity_id=entity_id) 
        response= json.dumps(db_response)
        return Response(response, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
    except Exception as e:
        error_msg=json.dumps({STATUS: ERROR,  ERROR_DES: str(e)})
        return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))            
    
@bp.route(rule="v1/send/notification/entity/self", methods=["POST"])
def send_entity_notification_to_mobile_by_fcm():
    try:
        #Get the json payload from the request find user_id notification title and body and action type
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))                        
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        user_id= payload.get("user_id", "")
        entity_id= payload.get("org_id", "")
        title= payload.get("title", "")        
        body= payload.get("body", "")
        image= payload.get("image", "")
        action= payload.get("action", "")        
        priority= payload.get("priority", "")
        
        if user_id is None or user_id == "":
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Invalid userid."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_locker_id_and_entity_id(user_id, entity_id)
        
        if status_code== 200:
            reg_id_list=[]#fcm token load here
            for row in db_response["response"]:
                reg_id_list.append(row["fcm_token"])
            
            dict_payload= {
                "registration_ids": reg_id_list, 
                "priority": priority, 
                "notification": {
                    "title": title,
                    "body": body,
                    "image": image
                },
                "data": {
                    "title": title,
                    "body": body,
                    "actionType": action,
                    "image": image
                }
            }
            
            if action is not None and (action== "webview" or action== "browser")  :
                url= payload.get("url", "")    
                web_page_title= payload.get("web_title", "")            
                main_payload= {
                    action: { 
                        "title": web_page_title, 
                        "url": url
                    }
                }                
            elif action is not None and action== "dialog" :
                url= payload.get("url", "")    
                dialog_messgae= payload.get("message", "")    
                dialog_title= payload.get("title", "")            
                main_payload= {
                    action: { 
                        "title": dialog_title, 
                        "message": dialog_messgae,
                        "image": url
                    }
                }
            elif action is not None and action== "store" :
                android_url= payload.get("playstore_url", "")    
                appstore_url= payload.get("appstore_url", "")    
                main_payload= {
                    action: { 
                        "playStoreUrl": android_url, 
                        "appStoreUrl": appstore_url
                    }
                }
            dict_payload["data"].update(main_payload)
            json_payload=json.dumps(dict_payload)            
            firebase_config= CONFIG["firebase_config"]
            headers={os.getenv("CONTENT_TYPE"): "application/json", "Authorization":"key="+firebase_config["fcm_auth_key"]}
            post_data= PostData(firebase_config["push_notificatetion_url"], header=headers, payload=json_payload)
            server_res= post_data.send_post_request()
            if server_res.status_code== 200:
                return json.loads(server_res.text)
            return jsonify({STATUS: ERROR,  ERROR_DES:"Unable to send firebase notification to entity." + str(e)}), 400                    
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:"Excption in sending notification to entity:::" + str(e)}), 400
    
@bp.route(rule="v1/send/notification/entity/alluser", methods=["POST"])
def send_notification_by_entity_id_to_mobile_by_fcm():
    try:
        #Get the json payload from the request find user_id notification title and body and action type
        payload= request.get_json()
        if not payload:
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "No payload provided."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))                        
        if not isinstance(payload, dict):
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Payload must be a json object."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        entity_id= payload.get("org_id", "")
        title= payload.get("title", "")        
        body= payload.get("body", "")
        image= payload.get("image", "")
        action= payload.get("action", "")        
        priority= payload.get("priority", "")
        
        if entity_id is None or entity_id == "":
            error_msg=json.dumps({ERROR: "error",  ERROR_DES: "Invalid organization id."})
            return Response(error_msg, status=400, content_type=os.getenv("APPLICATION_JSON"))
        
        device_utils= DeviceUtils()
        db_response, status_code= device_utils.find_devices_by_entity_id(entity_id)
        
        if status_code== 200:
            reg_id_list=[]#fcm token load here
            for row in db_response["response"]:
                reg_id_list.append(row["fcm_token"])
            
            dict_payload= {
                "registration_ids": reg_id_list, 
                "priority": priority, 
                "notification": {
                    "title": title,
                    "body": body,
                    "image": image
                },
                "data": {
                    "title": title,
                    "body": body,
                    "actionType": action,
                    "image": image
                }
            }
            main_payload= {}
            if action is not None and (action== "webview" or action== "browser"):
                url= payload.get("url", "")    
                web_page_title= payload.get("web_title", "")            
                main_payload= {
                    action: { 
                        "title": web_page_title, 
                        "url": url
                    }
                }                
            elif action is not None and action== "dialog":
                url= payload.get("url", "")    
                dialog_messgae= payload.get("message", "")    
                dialog_title= payload.get("title", "")            
                main_payload= {
                    action: { 
                        "title": dialog_title, 
                        "message": dialog_messgae,
                        "image": url
                    }
                }
            elif action is not None and action== "store":
                android_url= payload.get("playstore_url", "")    
                appstore_url= payload.get("appstore_url", "")    
                main_payload= {
                    action: { 
                        "playStoreUrl": android_url, 
                        "appStoreUrl": appstore_url
                    }
                }
            dict_payload["data"].update(main_payload)
            json_payload=json.dumps(dict_payload)            
            firebase_config= CONFIG["firebase_config"]
            headers={os.getenv("CONTENT_TYPE"): "application/json", "Authorization":"key="+firebase_config["fcm_auth_key"]}
            post_data= PostData(firebase_config["push_notificatetion_url"], header=headers, payload=json_payload)
            server_res= post_data.send_post_request()
            if server_res.status_code== 200:
                return json.loads(server_res.text)
            return jsonify({STATUS: ERROR,  ERROR_DES:"Unable to send firebase notification to entity." + str(e)}), 400
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:"Excption in sending notification to entity:::" + str(e)}), 400
    
    
    