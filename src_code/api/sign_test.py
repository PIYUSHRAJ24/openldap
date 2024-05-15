from urllib.parse import urlencode
from requests import post
from flask import Blueprint, request
from assets.test.sign import sample_pdfB64, sample_xmlB64
from lib.constants import *

bp = Blueprint('sign_test', __name__)
headers = {'Content-Type': 'application/x-www-form-urlencoded'}


@bp.before_request
def default():
    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_401'), RESPONSE: "JWT: " + str(e)}, 401


@bp.route('/healthcheck', methods=['GET'])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route('/esign/v1', methods=['POST'])
def esign_pdf():
    url = f"{CONFIG['testingurls']['signpdf']}/esign/v1"
    data = {
        'uri': request.values.get('uri', ''),
        'base64Data': sample_pdfB64,
        'signPosition': request.values.get('signPosition', '')
    }
    return post_request(url, data)


@bp.route('/qrgen/v1', methods=['POST'])
def qrgen():
    url = f"{CONFIG['testingurls']['signqr']}/qrgen/v1"
    data = {
        'uri': request.values.get('uri', ''),
        'qr_data': request.values.get('qr_data', ''),
        'doc_type': request.values.get('doc_type', '')
    }
    return post_request(url, data)


@bp.route('/signxml/v1', methods=['POST'])
def signxml():
    url = f"{CONFIG['testingurls']['signxml']}/signxml/v1"
    data = {
        'uri': request.values.get('uri', ''),
        'base64Data': sample_xmlB64
    }
    return post_request(url, data)


def post_request(url, data):
    hmac = {
        'client_id': request.values.get('client_id', ''),
        'ts': request.values.get('ts', ''),
        'hmac': request.values.get('hmac', '')
    }
    encoded_data = urlencode({**hmac, **data})
    try:
        res = post(url, headers=headers, data=encoded_data)
    except Exception as e:
        return {STATUS: ERROR, ERROR_DESCRIPTION: Errors.error('err_489'), RESPONSE: str(e)}, 400
    try:
        return res.json(), res.status_code
    except Exception:
        return res.text, res.status_code
