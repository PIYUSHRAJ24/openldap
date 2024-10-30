import json
import os
import time
import uuid
from flask import Blueprint, request, g
from datetime import datetime
import dotenv
import logging
from pythonjsonlogger import jsonlogger
import traceback
import sys
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
current_iso_timestamp = datetime.utcnow().isoformat() + "Z"
def log_uncaught_exceptions(exc_type, exc_value, exc_traceback):
    error_log_data = {
        'timestamp': current_iso_timestamp,
        'level': 'CRITICAL',
        'event': 'uncaught_exception',
        'error_type': exc_type.__name__,
        'error': str(exc_value),
        'traceback': ''.join(traceback.format_tb(exc_traceback)),
        'transaction_id': getattr(g, 'transaction_id', 'N/A')
    }
    logger.critical(json.dumps(error_log_data))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = log_uncaught_exceptions
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

@app.route('/healthcheck', methods=['GET'])
@app.route('/', methods=['GET'])
def healthcheck():
    return {"status": "success"}, 200

@app.before_request
def before_request():
    ''' before request'''
    try:
        g.start_time = time.time()
        g.after_request_logged = False
        g.transaction_id = request.headers.get('X-REQUEST-ID', str(uuid.uuid4()))
        log_data = {
            'timestamp': current_iso_timestamp,
            'level': 'INFO',
            'event': 'request_started',
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True),
            'transaction_id': g.transaction_id
        }
        logger.info(json.dumps(log_data))
    except Exception as e:
        error_log_data = {
            'timestamp': current_iso_timestamp,
            'level': 'ERROR',
            'event': 'before_request_error',
            'error': str(e),
            'traceback': traceback.format_exc(),
            'transaction_id': getattr(g, 'transaction_id', 'N/A')
        }
        logger.error(json.dumps(error_log_data))

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
app.register_blueprint(user_status_bp, url_prefix='/status')
app.register_blueprint(user_name_bp, url_prefix='/search/v1')
app.register_blueprint(count_bp, url_prefix='/')


@app.after_request
def after_request(response):
    try:
        g.after_request_logged = True
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'"
        response.headers['X-REQUEST-ID'] = getattr(g, 'transaction_id', str(uuid.uuid4()))
        
        duration = time.time() - getattr(g, 'start_time', time.time())
        log_data = {
            'timestamp': current_iso_timestamp,
            'level': 'INFO',
            'event': 'request_completed',
            'method': request.method,
            'url': request.url,
            'status_code': response.status_code,
            'duration': duration,
            'headers': dict(response.headers),
            'transaction_id': getattr(g, 'transaction_id', 'N/A')
        }
        logger.info(json.dumps(log_data))
        
        # Log successful responses
        if 200 <= response.status_code < 300:
            success_log_data = {
                'timestamp': current_iso_timestamp,
                'level': 'INFO',
                'event': 'successful_response',
                'method': request.method,
                'url': request.url,
                'status_code': response.status_code,
                'transaction_id': getattr(g, 'transaction_id', 'N/A')
            }
            logger.info(json.dumps(success_log_data))
        
        # Original logging logic
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True)
        }
        logger.info(f"Outgoing response: {json.dumps(response_data)}")
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Access-Control-Allow-Headers'] = 'x-requested-with, Content-Type, origin, authorization, Origin, Authorization, accept, jtoken, Jtoken, is_encrypted, client-security-token, requesttoken, XMLHttpRequest, Device-Security-Id, Source, device-security-id'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Permissions-Policy'] = 'geolocation=(self), microphone=()'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
        response.headers['Expect-CT'] = 'max-age=86400, enforce'
        ref = str(request.headers.get('Origin'))
        if ref is not None and ref in os.getenv('ALLOWED_ORIGIN'):
            response.headers.add("Access-Control-Allow-Origin", ref)
        else:
            response.headers.add("Access-Control-Allow-Origin", "https://entity.digilocker.gov.in")
        
        if "healthcheck" in request.url or getattr(g, 'after_request_logged', False):
            return response
        if "orgcount" in request.url or getattr(g, 'after_request_logged', False):
            return response
        
        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'time_end': current_iso_timestamp
        }
        log_data = {
            'request': request.logger_data,
            'response': response_data
        }
        logger.info(log_data)
        return response
    except Exception as e:
        print(f"Logging error: {str(e)}")
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    log_data = {
        'timestamp': current_iso_timestamp,
        'level': 'ERROR',
        'event': 'unhandled_exception',
        'error': str(e),
        'error_type': type(e).__name__,
        'traceback': tb,
        'request': {
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        },
        'user': getattr(g, 'user', None),
        'endpoint': request.endpoint,
        'args': request.args.to_dict(),
        'form': request.form.to_dict(),
        'json': request.json if request.is_json else None,
        'transaction_id': getattr(g, 'transaction_id', 'N/A'),
        'ip_address': request.remote_addr
    }
    
    # Log to file
    logger.error(json.dumps(log_data))

    # Return a generic error response
    response = {"status": "ERROR", "error_description": "Internal Server Error"}
    response['status_code'] = 400
    return response

WSGIRequestHandler.protocol_version = 'HTTP/1.1'
app.run(host=os.getenv('host'), port=int(os.getenv('port', 80)), debug=False)