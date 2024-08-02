'''
Created on 29-Nov-2022
-- to resize Image

@author: Kiran Tondchore
This API is for resize image

'''
import base64
from flask import request 
from PIL import Image
from flask import Blueprint, request
import time
bp = Blueprint('image', __name__)

import logging
from pythonjsonlogger import jsonlogger

# Setup logging
current_date = datetime.datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)


@bp.before_request
def before_request():
    try:
        pass
        
    except Exception as e:
        print(str(e))



@bp.route('/img_resize', methods=['POST'])
def img_resize():
    try:
        requested_time = str(time.time())
        file_name_ext = 'filename' + requested_time+'.jpg'
        x = request.values.get('x')
        y = request.values.get('y')
        basestr = request.values.get('base64')
        decodeit = open(file_name_ext, 'wb')
        decodeit.write(base64.b64decode((basestr)))
        decodeit.close()       
        im = Image.open(file_name_ext)
        resize = im.resize((int(x),int(y)))
        
        
        resize.save(file_name_ext,"jpeg")
        with open(file_name_ext, "rb") as image2string:
            converted_string = base64.b64encode(image2string.read())
        print(type(converted_string.decode()))
        
        return {"status":"success", "msg":"file resized","base64":converted_string.decode()}
    except Exception as e:
        return {"status":"error", "msg":"something went wrong", "actual_err":str(e)}

