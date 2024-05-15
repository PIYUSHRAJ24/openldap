import os

import dotenv

dotenv.load_dotenv()

from flask import Flask, request
from flask_cors import CORS
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
cors = CORS(app, origins=os.getenv('allowed_origin'))
app.config['SERVER_NAME'] = None

@app.after_request
def add_security_headers(response): 
    # referring_domain = request.referrer
    # allowed_domains = [
    #     'localhost',
    #     'https://entity.digilocker.gov.in',
    #     'http://entity.digilocker.gov.in',
    #     'https://entity.dl6.in',
    #     'https://dl-org-beta.dl6.in',
    #     'http://ashish.dl6.in'
    # ]
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
    # if referring_domain in allowed_domains:
    #     response.headers['Access-Control-Allow-Origin'] = referring_domain
    # else:
    #     response.headers['Access-Control-Allow-Origin'] = ''
    return response


from api.accounts_profile import bp as accounts_profile_bp
from api.activity import bp as activity_bp
from api.android_keystore_manager import bp as mystery_bp
from api.authlib import bp as authlib_bp
from api.cbse_result import bp as cbse_result_bp
from api.consent import consent_bp
from api.devices_data import bp as devices_bp
from api.filelock import bp as filelock_bp
# importing APIs
from api.healthcheck import bp as healthcheck_bp
from api.healthcheck_2 import bp as healthcheck_bp_2
from api.image import bp as image_bp
from api.location import bp as location_bp
from api.lockpdf import bp as lockpdf_bp
from api.metadata import bp as metadata_bp
from api.name_match import bp as name_match_bp
from api.org import bp as org_bp
from api.org_activity import bp as org_activity_bp
from api.otpservices import bp as otpservices_bp
from api.send_global_notification import bp as global_notification
from api.share import bp as share_bp
from api.capcha import bp as capcha_bp

from api.shared_profile_token import bp as shared_profile_token_bp
from api.sign_test import bp as sign_test_bp
from api.stats import bp as stats_bp
from api.uid_services import bp as uid_services_bp

# calling the APIs
app.register_blueprint(healthcheck_bp, url_prefix='/healthcheck')
app.register_blueprint(healthcheck_bp_2, url_prefix='/healthcheck_2')
app.register_blueprint(name_match_bp, url_prefix='/name_match')
app.register_blueprint(accounts_profile_bp, url_prefix='/profile')
app.register_blueprint(image_bp, url_prefix='/image')
app.register_blueprint(authlib_bp, url_prefix='')
#app.register_blueprint(validate_pin_bp, url_prefix='accounts')
app.register_blueprint(activity_bp, url_prefix='/activity')
app.register_blueprint(org_activity_bp, url_prefix='/org_activity')
app.register_blueprint(org_bp, url_prefix='/org')
app.register_blueprint(filelock_bp, url_prefix='/filelock')
app.register_blueprint(consent_bp, url_prefix='/consent')
app.register_blueprint(otpservices_bp, url_prefix='/aadhaar')
app.register_blueprint(metadata_bp, url_prefix='/metadata')
app.register_blueprint(lockpdf_bp, url_prefix='/lockpdf')
app.register_blueprint(devices_bp, url_prefix='/devices')
app.register_blueprint(stats_bp, url_prefix='/stats')
app.register_blueprint(sign_test_bp, url_prefix='/sign_test')
app.register_blueprint(location_bp, url_prefix ='/location')
app.register_blueprint(mystery_bp, url_prefix ='/mystery')
app.register_blueprint(uid_services_bp, url_prefix ='/uid_services')
app.register_blueprint(cbse_result_bp, url_prefix ='')
app.register_blueprint(shared_profile_token_bp, url_prefix ='')
app.register_blueprint(share_bp, url_prefix ='/share')
app.register_blueprint(global_notification, url_prefix='/global')
app.register_blueprint(capcha_bp, url_prefix='')


WSGIRequestHandler.protocol_version = 'HTTP/1.1'
app.run(host=os.getenv('host'), port=int(os.getenv('port', 80)), debug= os.getenv('debug_mode','').lower() == 'true')
