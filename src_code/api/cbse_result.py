import os
from dotenv import load_dotenv

from flask import Blueprint, request
from lib import cbselib
from lib.commonlib import CommonLib
load_dotenv()

db_name  = os.getenv('MONGO_DB_HELPDESK')
mongo_uri = os.getenv('MONGO_URI_HELPDESK')

cbse_connector = cbselib.Cbse(mongo_uri, db_name)

CommonLib = CommonLib()

bp = Blueprint('cbse_result', __name__)

@bp.route('/getStudentData/class10', methods=['POST'])
def getStudentData_class10():
    try:
        school_code = CommonLib.filter_cbse_input(field=request.values.get('school_code'))
        client_id = CommonLib.filter_cbse_input(field=request.values.get('clientid'))
        hmac = CommonLib.filter_cbse_input(field=request.values.get('hmac'))
        ts = CommonLib.filter_cbse_input(field=request.values.get('ts'))

        auth_key = cbse_connector.CheckAuthentication(client_id, hmac, school_code, ts)
        status_code, res = auth_key
        
        if status_code == 401 and res['status']=='error':
            return res, 401
        
        if school_code is None or len(school_code) !=5:
            return {"status": "error", "error_description": "Please provide valid School code."}, 400
        
        #get the data of class X cbsc
        query = {'school_code':school_code,"class": "X"}
        code, response = cbse_connector.schoolcode_exists(query, school_code, "X")
    
        if code == 200 and len(response)>0 :
           return {"status": "success", "data":response}, code
        else:
            return {"status": "error", "error_description":"No record found."}, 400
    except Exception as e:
        return {"status": "error", "error_description": str(e)}, 400

@bp.route('/getStudentData/class12', methods=['POST'])
def getStudentData_class12():
    try:
        school_code = CommonLib.filter_cbse_input(field=request.values.get('school_code'))
        client_id = CommonLib.filter_cbse_input(field=request.values.get('clientid'))
        hmac = CommonLib.filter_cbse_input(field=request.values.get('hmac'))
        ts = CommonLib.filter_cbse_input(field=request.values.get('ts'))
        
        auth_key = cbse_connector.CheckAuthentication(client_id, hmac, school_code, ts)
       
        status_code, res = auth_key
        
        if status_code == 401 and res['status']=='error':
            return res, 401
        
        if school_code is None or len(school_code) !=5:
            return {"status": "error", "error_description": "Please provide valid School code!"}, 400
        
        #get the data of class XII cbsc
        query = {'school_code':school_code,"class": "XII"}
        code, response = cbse_connector.schoolcode_exists(query, school_code, "XII")
        if code == 200 and len(response)>0 :
           return {"status": "success", "data":response}, code
        else:
            return {"status": "error", "error_description":"No record found."}, 400
    except Exception as e:
        return {"status": "error", "error_description": str(e)}, 400


@bp.route('/insert_test', methods=['GET'])
def insert_test():
    try:
        d = cbse_connector.ins()
        return d
    except Exception as e:
        return {"status": "error", "error_description": str(e)}, 400

@bp.route('/delete_test', methods=['GET', 'POST'])
def iddd_test():
    try:
        roll = request.values.get('roll')
        d = cbse_connector.ddd(roll)
        return d
    except Exception as e:
        return {"status": "error", "error_description": str(e)}, 400
    
    