import os
import lib.utils as utils
from lib.utils import SignData, PostData, load_credential
from lib.rabbitmq import RabbitMQ
from flask import request, Blueprint, Response, json, g, jsonify
from dotenv import load_dotenv
from lib.authenticator import ValidateUser

from datetime import datetime
from lib.constants import ERROR, ERROR_DESCRIPTION, RESPONSE


load_dotenv()
now= datetime.now()
consent_bp= Blueprint("consent_mediator", __name__)
logarray = {}
logs_mq = RabbitMQ()
logs_queue_name= "acsapi_consent_logs_"
errorDescription= "errorDescription"
connect_timeout= 5
read_timeout= 40

load_credential()

@consent_bp.after_request
def add_header(response) :
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Permissions-Policy"] = "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()"
    return response

@consent_bp.before_request
def before_request():
    try:        
        if request.method== os.getenv("OPTIONS"):
            return json.dumps({ERROR: "error", ERROR_DESCRIPTION: "OPTIONS_OK"})
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
        return Response(json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Exception(JWT):" + str(e)}), status=401, content_type=os.getenv("APPLICATION_JSON"))
    
@consent_bp.route("/v1/find_by_sub", methods=["GET"])
@consent_bp.route("/v1/find_by_sub/", methods=["GET"])
@consent_bp.route("/v1/find_by_sub/<page>", methods=["GET"])
def find_consent_by_subject(page= None):    
    status_code= 200
    try:
        url= os.getenv("CONSENT_DOMAIN")+os.getenv("CONSENT_FIND__BY_SUB")+g.user_data.get("locker_id")
        status_code, data= utils.load_private_key_pem_as_bare_base64()
        if status_code!= 200:
            error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: data.get("message")})
            logarray.update({"status_code":status_code,  "date": now.strftime("%d-%m-%Y, %H:%M:%S"),  ERROR_DESCRIPTION: data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        data_signer= SignData(data.get("key"), g.user_data)        
        status_code, signed_data=data_signer.sign_data()        
        if(status_code != 200) :            
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: signed_data.get("message")})
            logarray.update({"status_code":status_code,  "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: signed_data.get("message")})            
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        if page is not None:            
            url= url+"?page="+str(page)
        header= {os.getenv("CONTENT_TYPE") : os.getenv("FORM_URL_ENCODED"), os.getenv("X_CONSENT_APPID_HEADER") : os.getenv("CONSENT_APPID"), "Authorization": "Bearer "+signed_data.get("jwt_token")}
        post_data= PostData(url, header)
        server_res= post_data.send_get_request()        
        status_code= server_res.status_code
        if status_code != 200:
            if status_code == 404:
                response="Something went wrong, Plz try after sometime:::[404]"
                error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: response})
            else:
                response= json.loads(server_res.text)
                error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: response[errorDescription]})
            logarray.update({"status_code":status_code, "url": url, "header":header, ERROR_DESCRIPTION: response[errorDescription], "date": now.strftime("%d-%m-%Y, %H:%M:%S")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        return Response(server_res.text, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
    except Exception as e:
        status_code= 400
        error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Exception:In finding consent list::" + str(e)})
        logarray.update({"status_code":status_code, "url": url, ERROR_DESCRIPTION: str(e), "date": now.strftime("%d-%m-%Y, %H:%M:%S")})
        logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
        return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
    
@consent_bp.route("/v1/revoke/<ack_id>", methods=["PATCH"])
@consent_bp.route("/v1/revoke/<ack_id>/", methods=["PATCH"])
def revoke_consent_by_ack(ack_id= None):
    status_code= 200
    try:
        if ack_id is None or ack_id== "":
            status_code= 400
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Plz check the acknoledgement id."})
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        url= os.getenv("CONSENT_DOMAIN")+os.getenv("CONSENT_REVOKE")+ack_id
        status_code, data= utils.load_private_key_pem_as_bare_base64()
        if status_code!= 200:
            error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        data_signer= SignData(data.get("key"), g.user_data, ack_id)
        status_code, signed_data=data_signer.sign_data()        
        if(status_code != 200) :
            error_msg=json.dumps({ERROR: "", ERROR_DESCRIPTION: signed_data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: signed_data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        header= {os.getenv("X_CONSENT_APPID_HEADER") : os.getenv("CONSENT_APPID"), "Authorization": "Bearer "+signed_data.get("jwt_token")}
        post_data= PostData(url, header)
        server_res= post_data.send_patch_request()        
        status_code= server_res.status_code
        if status_code != 204:
            response= json.loads(server_res.text)
            error_msg= json.dumps({ERROR:"error", ERROR_DESCRIPTION: response[errorDescription]})
            logarray.update({"status_code":status_code, "url": url, "header":header, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION:  response[errorDescription]})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        return  Response(status=status_code)        
    except Exception as e:
        status_code= 400
        error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Exception: Revoke consent::" + str(e)})
        logarray.update({"status_code":status_code, "url": url, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: str(e)})
        logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
        return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
    
@consent_bp.route("/v1/update/<ack_id>", methods=["PATCH"])
@consent_bp.route("/v1/update/<ack_id>/", methods=["PATCH"])
def update_consent_by_ack(ack_id= None):
    status_code= 200
    try:
        if ack_id is None or ack_id== "":
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Plz check the acknoledgement id."})
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        request_data = request.get_json()
        if not request_data:
            return jsonify({ERROR: "error",  ERROR_DESCRIPTION: "No payload provided."}), 400        
        if not isinstance(request_data, dict):
            return jsonify({ERROR: "error",  ERROR_DESCRIPTION: "Payload must be an object."}), 400        
        if request_data.get("scope") is None or request_data.get("scope")== "":
            status_code= 400            
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Invalid request parameters."})
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))                
        if request_data.get("expireTo") is None or request_data.get("expireTo")== "":
            status_code= 400            
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Invalid request parameters."})
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        url= os.getenv("CONSENT_DOMAIN")+os.getenv("CONSENT_UPDATE")+ack_id        
        status_code, data= utils.load_private_key_pem_as_bare_base64()
        if status_code!= 200:
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        data_signer= SignData(data.get("key"), g.user_data, ack_id)
        status_code, signed_data=data_signer.sign_data()        
        if(status_code != 200) :
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: signed_data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION: signed_data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))                
        header= {os.getenv("CONTENT_TYPE") : os.getenv("APPLICATION_JSON"), os.getenv("X_CONSENT_APPID_HEADER") : os.getenv("CONSENT_APPID"), "Authorization": "Bearer "+signed_data.get("jwt_token")}
        payload= json.dumps({"scope": request_data.get("scope"), "expireTo": request_data.get("expireTo")})
        post_data= PostData(url, header, payload)
        server_res= post_data.send_patch_request()
        status_code= server_res.status_code
        if status_code != 204:
            response= json.loads(server_res.text)
            error_msg= json.dumps({ERROR:"error", ERROR_DESCRIPTION: response[errorDescription]})
            logarray.update({"status_code":status_code, "url": url, "header":header, "payload": payload, "date": now.strftime("%d-%m-%Y, %H:%M:%S"), ERROR_DESCRIPTION:  response[errorDescription]})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        return  Response(status=status_code)
    except Exception as e:
        status_code= 400
        error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Exception:In Updating Consent data::" + str(e)})
        logarray.update({"status_code":status_code,  RESPONSE: error_msg, "url": url, "date": now.strftime("%d-%m-%Y, %H:%M:%S")})
        logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
        return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))

@consent_bp.route("/v1/pending", methods=["GET"])
@consent_bp.route("/v1/pending/", methods=["GET"])
@consent_bp.route("/v1/pending/<page>", methods=["GET"])
def get_pending_consent(page= None):
    status_code= 200
    try:
        user_id= g.user_data.get("locker_id")        
        url= (os.getenv("CONSENT_DOMAIN")+(os.getenv("CONSENT_PENDING")).format(user_id=user_id))
        status_code, data= utils.load_private_key_pem_as_bare_base64()
        if status_code!= 200:
            error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"),  ERROR_DESCRIPTION: data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        data_signer= SignData(data.get("key"), g.user_data)        
        status_code, signed_data=data_signer.sign_data()        
        if(status_code != 200) :
            error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: signed_data.get("message")})
            logarray.update({"status_code":status_code, "date": now.strftime("%d-%m-%Y, %H:%M:%S"),  ERROR_DESCRIPTION: signed_data.get("message")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))        
        if page is not None:            
            url= url+"?page="+str(page)
        header= {os.getenv("CONTENT_TYPE") : os.getenv("FORM_URL_ENCODED"), os.getenv("X_CONSENT_APPID_HEADER") : os.getenv("CONSENT_APPID"), "Authorization": "Bearer "+signed_data.get("jwt_token")}
        post_data= PostData(url, header)
        server_res= post_data.send_get_request()        
        status_code= server_res.status_code
        if status_code != 200:
            if status_code == 404:
                response="Something went wrong, Plz try after sometime:::[404]"
                error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: response})
            else:
                response= json.loads(server_res.text)
                error_msg=json.dumps({ERROR: "error", ERROR_DESCRIPTION: response[errorDescription]})
            logarray.update({"status_code":status_code, "url": url, "header":header, ERROR_DESCRIPTION: response[errorDescription], "date": now.strftime("%d-%m-%Y, %H:%M:%S")})
            logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
            return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
        return Response(server_res.text, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
    except Exception as e:
        status_code= 400
        error_msg= json.dumps({ERROR: "error", ERROR_DESCRIPTION: "Exception:In finding consent list::" + str(e)})
        logarray.update({"status_code":status_code, "url": url, ERROR_DESCRIPTION: str(e), "date": now.strftime("%d-%m-%Y, %H:%M:%S")})
        logs_mq.send_to_logstash(logarray, 'Logstash_Xchange', logs_queue_name)
        return Response(error_msg, status=status_code, content_type=os.getenv("APPLICATION_JSON"))
