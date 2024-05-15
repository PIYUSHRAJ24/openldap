import os

from flask import Blueprint, Response, g, json, jsonify, request
from lib.constants import CONFIG, ERROR, ERROR_DES, RESPONSE, STATUS, SUCCESS
from lib.utils import PostData, load_credential

bp= Blueprint("global", __name__)
status_code= 200

load_credential()

@bp.before_request
def before_request():
    ''' before requests'''
    try:
        if request.method== os.getenv("METHOD_OPTIONS"):
            return json.dumps({STATUS: ERROR, ERROR_DES: "OPTIONS_OK"})
        bypass_urls = ("healthcheck")
        if request.path.split('/')[1] in bypass_urls:
            return
        g.xval= request.headers.get("X-VALUE", None)
        sec_key= CONFIG['DEVICE_CRED'].get('NOTIFICATION_SECRET_KEY')
        if(g.xval!= sec_key) :
            return Response(json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorised Access!"}), status=401, content_type=os.getenv("APPLICATION_JSON"))
    except Exception as e:
        return Response(json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorised Access!:" + str(e)}), status=401, content_type=os.getenv("APPLICATION_JSON"))

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

@bp.route(rule="/v1/notification", methods=["POST"])
def send_data_to_app():
    try:        
        payload= request.get_json()
        if payload is None or str(payload) == "":
            res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Invalid request."})                    
            return Response(res_data, status=400, content_type="application/json")
        else:
            topic=payload.get("topic", "")
            title= payload.get("title", "")
            body= payload.get("body", "")        
            org_id= payload.get("org_id", "")
            action= payload.get("action", "")        
            doc_type= payload.get("doc_type", "")
            dict_payload= {
                "to": topic,
                "notification": {
                    "title": title,
                    "body": body
                },
                "data": {
                    "title": title,
                    "body": body,
                    "actionType": action,
                    action: {
                        "org_id": org_id,
                        "doc_type": doc_type
                    }
                }
            }
            json_payload=json.dumps(dict_payload)
            firebase_config= CONFIG["firebase_config"]
            headers={os.getenv("CONTENT_TYPE"): "application/json", "Authorization":"key="+firebase_config["fcm_auth_key"]}
            post_data= PostData(firebase_config["push_notificatetion_url"], header=headers, payload=json_payload)
            server_res= post_data.send_post_request()
            if server_res.status_code== 200:                
                return server_res.text, 200
            return jsonify({STATUS: ERROR,  ERROR_DES:"Unable to send firebase notification."}), 400
    except Exception as e:
        return jsonify({STATUS: ERROR,  ERROR_DES:"Exception in sending notification to DigiLocker Users::::::" + str(e)}), 400
    
    