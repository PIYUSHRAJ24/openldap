import os

from flask import Blueprint, Response, g, json, request
from lib.constants import CONFIG, ERROR, ERROR_DES, RESPONSE, STATUS, SUCCESS
from lib.cryptographer import Crypt
from lib.secretsmanager import SecretManager
from lib.utils import load_apk_signature, load_credential

bp= Blueprint("mystery", __name__)
status_code= 200
load_credential()
load_apk_signature()
apk_sign_key_hash= CONFIG["apk_signin_key_hash_new"]

@bp.after_request
def add_header(response) :
    ''' add header'''
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Permissions-Policy"] = "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()"
    response.headers['K-TYPE'] = g.ktype    
    if hasattr(g, 'xval') and g.xval is not None and g.xval != "":
        response.headers['X-VALUE'] = str(g.xval)
    else:
        response.headers['X-VALUE'] = ""
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
        g.ktype= request.headers.get("K-TYPE", None)
        g.hash= request.headers.get("X-VALUE", None)
        if g.ktype== "r" :
            g.skey= apk_sign_key_hash["r_key"]
        elif g.ktype== "d" or g.ktype== "ed":
            g.skey= apk_sign_key_hash["d_key"] 
        elif g.ktype== "er" :
            g.skey= apk_sign_key_hash["er_key"] 
        elif g.ktype== "indus_r" :
            g.skey= apk_sign_key_hash["indus_app_r_key"] 
        elif g.ktype== "indus_er" :
            g.skey= apk_sign_key_hash["indus_app_er_key"] 
        else:
            return Response(json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorised Access!"}), status=401, content_type=os.getenv("APPLICATION_JSON"))
    except Exception as e:
        return Response(json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorised Access!:" + str(e)}), status=401, content_type=os.getenv("APPLICATION_JSON"))

@bp.route(rule="/v1/initials", methods=["POST"])
def send_data_to_app():
    g.xval= ""
    request_data= request.data        
    crypt= Crypt(g.skey)
    
    if request_data is None or str(request_data) == "":
        res_data= json.dumps({"txn": txn, STATUS:ERROR, ERROR_DES: "Invalid request."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)        
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    data= request_data.decode('utf-8')    
    status_code, dec_data= crypt.dec_aes_cbc_256(data)    
    if status_code!= 200:
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorized request data"})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    status_code, req_hash= crypt.make_sha_256_hash(dec_data)
    if g.hash != req_hash :
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Request from unauthorized source."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    req_json= json.loads(dec_data)
    txn=  req_json.get("txn", None)
    
    if  txn is None or txn== "":
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Invalid transaction."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    sec_key= CONFIG['DEVICE_CRED'].get('JWT_SECRET')
    app_cipher= CONFIG['DEVICE_CRED'].get('APP_ENCRYPTION_KEY')
    res_json= {
        "txn":txn,
        "status":SUCCESS,
        "native_salt":sec_key,
        "native_app_cipher":app_cipher,
        "crypto_pref_key":"9rQ78aelO4/5qqn0V85ohg==",
        "key_for_aes":"yV14meTSPbJeFTpkixfQhQ==",
        "data_crypt_algo_key":"su0Y5tq9LUxPIawPTZmVEg==",
        "alias_key":"OLTICdp2FSuuD2QW19zEfQ==",
        "keystore_pwd":"M3MeDLNX30yJjtpCuunExw==",
        "android_keystore_key":"7chG3Wf/VNRIpLorvibomg==",
        "rsa_mode_key":"NgqSpXgNz/9nn1vyGFtpKslbkQKexVzQo9IJoaJq/tQ="
    }
    status_code, g.xval= crypt.make_sha_256_hash(json.dumps(res_json))    
    
    status_code, response= crypt.enc_aes_cbc_256(json.dumps(res_json))
    return Response(response, status=200, content_type="text/plain")

@bp.route(rule="/v1/entity/initials", methods=["POST"])
def send_data_to_entity_app():
    g.xval= ""
    request_data= request.data    
    crypt= Crypt(g.skey)
    if request_data is None or str(request_data) == "":
        res_data= json.dumps({"txn": txn, STATUS:ERROR, ERROR_DES: "Invalid request."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)        
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    data= request_data.decode('utf-8')    
    status_code, dec_data= crypt.dec_aes_cbc_256(data)    
    if status_code!= 200:
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Unauthorized request data"})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    status_code, req_hash= crypt.make_sha_256_hash(dec_data)
    if g.hash != req_hash :
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Request from unauthorized source."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")
    
    req_json= json.loads(dec_data)
    txn=  req_json.get("txn", None)
    
    if  txn is None or txn== "":
        res_data= json.dumps({STATUS:ERROR, ERROR_DES: "Invalid transaction."})
        status_code, response= crypt.enc_aes_cbc_256(res_data)
        g.xval= ""
        return Response(response, status=400, content_type="text/plain")    
    sec_key= CONFIG['DEVICE_CRED'].get('JWT_SECRET')
    app_cipher= CONFIG['DEVICE_CRED'].get('APP_ENCRYPTION_KEY')
    res_json= {
        "txn":txn,
        "status":SUCCESS,
        "app_key":sec_key, 
        "native_app_cipher":app_cipher
    }
    status_code, g.xval= crypt.make_sha_256_hash(json.dumps(res_json))
    status_code, response= crypt.enc_aes_cbc_256(json.dumps(res_json))
    return Response(response, status=200, content_type="text/plain")