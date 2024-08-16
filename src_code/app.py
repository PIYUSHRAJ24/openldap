import os
from flask import Blueprint, request, g
from datetime import datetime
import dotenv
import logging
from pythonjsonlogger import jsonlogger
import traceback
dotenv.load_dotenv()
from flask import Flask
from flask_cors import CORS
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
cors = CORS(app, origins=os.getenv('allowed_origin'))
app.config['SERVER_NAME'] = None

current_date = datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-AUTH-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
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
    g.after_request_logged = False
    request_data = {
        'time_start': datetime.datetime.now(datetime.UTC),
        'method': request.method,
        'url': request.url,
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True)
    }
    request.logger_data = request_data

from api.filelock import bp as filelock_bp
# importing APIs
from api.image import bp as image_bp
# from api.lockpdf import bp as lockpdf_bp
# from api.metadata import bp as metadata_bp
from api.name_match import bp as name_match_bp
from api.org import bp as org_bp
from api.org_activity import bp as org_activity_bp
from api.otpservices import bp as otpservices_bp
from api.pin import bp as pin_bp
from api.signin import bp as signin_bp
from api.pan import bp as pan_bp
from api.gstin import bp as gstin_bp
from api.cin import bp as cin_bp
from api.hmac_cin import bp as hmac_cin_bp
from api.udyam import bp as udyam_bp

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
app.register_blueprint(udyam_bp, url_prefix='/udyam')


@app.datetime.datetime.now(datetime.UTC)
def after_request(response):
    try:
        if "healthcheck" in request.url:
            return response
        if getattr(g, 'after_request_logged', False):
            return response
        if g.after_request_logged:
            return response
        response.headers['Content-Security-Policy'] = "default-src 'self'"
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
        
        
        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'time_end': datetime.datetime.now(datetime.UTC)
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
        'error': str(e),
        'traceback': tb,
        'time': datetime.datetime.now(datetime.UTC),
        'request': {
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
    }
    logger.info(log_data)

    # Return a generic error response
    response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
    response.status_code = 500
    return response

WSGIRequestHandler.protocol_version = 'HTTP/1.1'
app.run(host=os.getenv('host'), port=int(os.getenv('port', 80)), debug=False)