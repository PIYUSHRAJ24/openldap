import os

import dotenv

dotenv.load_dotenv()

from flask import Flask
from flask_cors import CORS
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
cors = CORS(app, origins=os.getenv('allowed_origin'))
app.config['SERVER_NAME'] = None


@app.route('/healthcheck', methods=['GET'])
@app.route('/', methods=['GET'])
def healthcheck():
    return {"status": "success"}, 200

from api.filelock import bp as filelock_bp
# importing APIs
from api.image import bp as image_bp
# from api.lockpdf import bp as lockpdf_bp
# from api.metadata import bp as metadata_bp
from api.name_match import bp as name_match_bp
from api.org import bp as org_bp
from api.orgc import bp as orgc_bp
from api.org_activity import bp as org_activity_bp
from api.otpservices import bp as otpservices_bp
from api.pin import bp as pin_bp
from api.signin import bp as signin_bp
from api.pan import bp as pan_bp
from api.gstin import bp as gstin_bp
from api.cin import bp as cin_bp
from api.udyam import bp as udyam_bp

# calling the APIs
app.register_blueprint(name_match_bp, url_prefix='/name_match')
app.register_blueprint(image_bp, url_prefix='/image')
app.register_blueprint(org_activity_bp, url_prefix='/org_activity')
app.register_blueprint(org_bp, url_prefix='/org')
app.register_blueprint(orgc_bp, url_prefix='/orgc')
app.register_blueprint(filelock_bp, url_prefix='/filelock')
# app.register_blueprint(metadata_bp, url_prefix='/metadata')
# app.register_blueprint(lockpdf_bp, url_prefix='/lockpdf')
app.register_blueprint(otpservices_bp, url_prefix='/aadhaar')
app.register_blueprint(pin_bp, url_prefix='/pin')
app.register_blueprint(signin_bp, url_prefix='/signin')
app.register_blueprint(pan_bp, url_prefix='/pan')
app.register_blueprint(gstin_bp, url_prefix='/gstin')
app.register_blueprint(cin_bp, url_prefix='/cin')
app.register_blueprint(udyam_bp, url_prefix='/udyam')

WSGIRequestHandler.protocol_version = 'HTTP/1.1'
app.run(host=os.getenv('host'), port=int(os.getenv('port', 80)), debug= os.getenv('debug_mode','').lower() == 'true')