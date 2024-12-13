import json
import os
import time
import uuid
from flask import Blueprint, jsonify, request, g
from datetime import datetime
import dotenv
import logging
from pythonjsonlogger import jsonlogger
import traceback
import sys
from lib.constants import *
dotenv.load_dotenv()
from flask import Flask
from flask_cors import CORS
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
cors = CORS(app, origins=os.getenv('ALLOWED_ORIGIN'))
app.config['SERVER_NAME'] = None

current_date = datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-AUTH-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)


from api.filelock import bp as filelock_bp
# importing APIs
from api.image import bp as image_bp
from api.auth import bp as auth_bp
# from api.lockpdf import bp as lockpdf_bp
# from api.metadata import bp as metadata_bp
from api.name_match import bp as name_match_bp
from api.org import bp as org_bp
from api.org_activity import bp as org_activity_bp
from api.otpservices import bp as otpservices_bp
from api.pin import bp as pin_bp
from api.signin import bp as signin_bp
from api.pan import bp as pan_bp
from api.hmac_pan import bp as hmac_pan_bp
from api.gstin import bp as gstin_bp
from api.cin import bp as cin_bp
from api.hmac_cin import bp as hmac_cin_bp
from api.udyam import bp as udyam_bp
from api.hmac_udyam import bp as hmac_udyam_bp
from api.department import bp as department_bp
from api.permission import bp as permission_bp
from api.section import bp as section_bp
from api.users import bp as users_bp
from api.user_status import bp as user_status_bp
from api.user_name import bp as user_name_bp
from api.count import bp as count_bp
from api.gst import bp as gst_bp

# calling the APIs
app.register_blueprint(name_match_bp, url_prefix='/name_match')
app.register_blueprint(image_bp, url_prefix='/image')
app.register_blueprint(org_activity_bp, url_prefix='/org_activity')
app.register_blueprint(org_bp, url_prefix='/org')
app.register_blueprint(filelock_bp, url_prefix='/filelock')
app.register_blueprint(otpservices_bp, url_prefix='/aadhaar')
app.register_blueprint(pin_bp, url_prefix='/pin')
app.register_blueprint(signin_bp, url_prefix='/signin')
app.register_blueprint(pan_bp, url_prefix='/pan')
app.register_blueprint(gstin_bp, url_prefix='/gstin')
app.register_blueprint(cin_bp, url_prefix='/cin')
app.register_blueprint(hmac_cin_bp, url_prefix='/hmac_cin')
app.register_blueprint(hmac_pan_bp, url_prefix='/hmac_pan')
app.register_blueprint(hmac_udyam_bp, url_prefix='/hmac_udyam')
app.register_blueprint(udyam_bp, url_prefix='/udyam')
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(department_bp, url_prefix='/department')
app.register_blueprint(permission_bp, url_prefix='/permission')
app.register_blueprint(section_bp, url_prefix='/section')
app.register_blueprint(users_bp, url_prefix='/users')
app.register_blueprint(gst_bp, url_prefix='/gst')
app.register_blueprint(user_status_bp, url_prefix='/status')
app.register_blueprint(user_name_bp, url_prefix='/search/v1')
app.register_blueprint(count_bp, url_prefix='/')

@app.before_request
def before_request():
    ''' before request'''
    g.request_id = str(uuid.uuid4())
    g.after_request_logged = False
    request_data = {
        'time_start': datetime.utcnow().isoformat(),
        'method': request.method,
        'endpoint': request.path,
        'url': request.url,
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True),
        'request': {}
    }
    if dict(request.args):
        request_data[REQUEST].update(dict(request.args))
    if dict(request.values):
        request_data[REQUEST].update(dict(request.values))
    if request.headers.get('Content-Type') == "application/json":
        request_data[REQUEST].update(dict(request.json))
    request.logger_data = request_data


@app.after_request
def after_request(response):
    try:
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
        response.headers['Permissions-Policy'] = 'geolocation=(self), microphone=()'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
        response.headers['Expect-CT'] = 'max-age=86400, enforce'
        ref = str(request.headers.get('Origin'))
        if ref is not None and ref in os.getenv('allowed_origin'):
            response.headers.add("Access-Control-Allow-Origin", ref)
        else:
            response.headers.add("Access-Control-Allow-Origin", "https://www.digilocker.gov.in")
        
        response.headers["Server"] = "Hidden"
        
        if request.path in ('/healthcheck/', '/'):
            g.after_request_logged = True
        
        ''' Skip logging for after_request_logged == True '''
        if getattr(g, 'after_request_logged', False):
            return response
        if g.after_request_logged:
            return response
        
        try:
            tech_msg = response.json.pop(RESPONSE, None)
        except Exception:
            tech_msg = response.get_data(as_text=True)
        try:
            code = response.status_code
        except Exception:
            code = 400

        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'error': tech_msg,
            'status_code': code,
            'time_end': datetime.datetime.utcnow().isoformat()
        }
        
        log_data = {
            'request_id': g.request_id,
            'request': getattr(request, 'logger_data', {}),
            'response': response_data
        }
        logger.info(log_data)
        g.after_request_logged = True
        return response
    except Exception as e:
        print(f"Logging error: {str(e)}")
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    ''' final error excpetion handler'''
    tb = traceback.format_exc()
    log_data = {
        'error': str(e),
        'traceback': tb,
        'time': datetime.datetime.utcnow().isoformat(),
        'endpoint': request.path,
        'request': {
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
    }
    logger.error(log_data)
    response = jsonify({STATUS: ERROR, ERROR_DES: "Some technical error occurred."})
    response.status_code = 400
    return response

@app.route('/', methods=['GET', 'POST'])
def index():
    return {"status": "success"}

WSGIRequestHandler.protocol_version = 'HTTP/1.1'
app.run(host=os.getenv('host'), port=int(os.getenv('port', 80)), debug=False)