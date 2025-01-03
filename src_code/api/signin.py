import base64
import hashlib
import re, time, requests
from datetime import datetime, timezone
from flask import request, Blueprint, g, jsonify
from lib.constants import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from lib.commonlib import CommonLib
from lib.secretsmanager import SecretManager
from lib.validations import Validations
from lib.mongolib import MongoLib
from lib.redislib import RedisLib
from lib.drivejwt import DriveJwt

get_ttl = configparser.ConfigParser()
get_ttl.read("lib/cache_ttl.ini")

VALIDATIONS = Validations()
MONGOLIB = MongoLib()
# RABBITMQ = RabbitMQ()
REDISLIB = RedisLib()

accounts_eve = CONFIG["accounts_eve"]
org_eve = CONFIG["org_eve"]

logs_queue = "org_sighin_user_"
bp = Blueprint("signin", __name__)

logarray = {}


@bp.before_request
def validate_user():
    """
    JWT Authentication
    """
    try:        
        if request.method == "OPTIONS":
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = "healthcheck"
        if (
            request.path.split("/")[1] in bypass_urls
            or request.path.split("/")[-1] in bypass_urls
        ):
            return
        g.endpoint = request.path

        jwtlib = DriveJwt(request)

        jwtres, status_code = jwtlib.jwt_login_org()

        if status_code != 200:
            return jwtres, status_code
        g.path = jwtres
        g.jwt_token = jwtlib.jwt_token
        g.did = jwtlib.device_security_id
        g.digilockerid = jwtlib.digilockerid
        g.org_id = jwtlib.org_id
        logarray.update({"org_id": g.org_id, "digilockerid": g.digilockerid})
    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {STATUS: ERROR, ERROR_DES: Errors.error('err_1201')+"[#1500]"}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return {STATUS: SUCCESS}


@bp.route("/get_multiuser_clients", methods=["GET"])
def get_multiuser_clients():
    try:
        aadhar = request.form.get("aadhar")
        mobile_no = request.form.get("mobile_no")

        if not aadhar and not mobile_no:
            return {
                "status": "error",
                "response": "Please enter a valid mobile number or aadhar number",
            }, 400

        if aadhar and not re.match(r"^\d{12}$", aadhar):
            return {"status": "error", "response": "Invalid Aadhar number"}, 400

        if mobile_no and not re.match(r"^\d{10}$", mobile_no):
            return {"status": "error", "response": "Invalid mobile number"}, 400

        if aadhar:
            users, status_code = get_users(aadhar, "other")
        else:
            query = {"mobile_no": mobile_no}
            fields = {}
            responce, status_code = MONGOLIB.accounts_eve(
                accounts_eve['collection_usr'], query, fields, limit=1
            )
            if status_code != 200:
                return {
                    "status": "error",
                    "response ": "Not Found",
                }, status_code
                   

            users = []
            if responce["status"] == "success":
                user_info = responce["response"][0]
                
                if 'org_id' not in user_info:
                    return {
                        "status": "success",
                        "response :- ": "User not linked any organization",
                    } , status_code
                    
                    
                if user_info["digilockerid"]:
                    digilockerid = user_info["digilockerid"]
                    user_type = user_info["user_type"]
                    user_id = user_info["user_id"]
                    org_ids = user_info["org_id"]

                    output_dict = {
                        "digilockerid": digilockerid,
                        "name": get_user_name(digilockerid),
                        "user_type": user_type,
                        "user_id": user_id,
                        "org_id_exists": org_ids,
                    }

                users.append(output_dict)
                responce["response"] = users
                usr = responce

        if status_code != 200:
            return users, status_code

        if aadhar:
            filtered_data = filter_data(users)
        else:
            filtered_data = filter_data(usr)

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {
            "status": "error",
            "response": Errors.error('err_1201')+"[#1501]",
        }, 500

    return filtered_data, 200

def filter_data(response):
    filtered_data = []
    client_secret = CONFIG["org_signin_api"]["client_secret"]

    for user in response["response"]:
        if "org_id_exists" in user and user["org_id_exists"]:
            for org_id in user["org_id_exists"]:
                is_valid_organization = check_for_organization(
                    user.get("digilockerid", ""), org_id
                )
                if is_valid_organization is not None:
                    data_as_per_org = user.copy()

                    data_as_per_org["digilockerid"] = CommonLib.aes_encryption_v3(
                        user.get("digilockerid", ""), client_secret
                    )

                    data_as_per_org["user_id"] = CommonLib.aes_encryption_v3(
                        user["user_id"], client_secret
                    )

                    data_as_per_org["orgs"] = [is_valid_organization]
                    if "org_id" in data_as_per_org:
                        del data_as_per_org["org_id"]
                    filtered_data.append(data_as_per_org)

    if filtered_data:
        return {"status": "success", "response": filtered_data}
    else:
        return {"status": "error", "response": "Not found"}


def check_for_organization(lockerid, org_id):
    res = get_org_details_based_on_lockerid(lockerid)
    if res.get("status") == "success" and res.get("response"):
        for org in res["response"]:
            if org["org_id"] == org_id and org["is_active"] == "Y":
                return {
                    "org_id": org["org_id"],
                    "org_name": org.get("org_name", org["org_id"]),
                }
    return None


def get_org_details_based_on_lockerid(lockerid=None):

    url = CONFIG["org_signin_api"]["url"] + "/org/get_access_rules?digilockerid="+lockerid

    payload = {}
    files={}
    headers = {}

    ts = str(int(time.time()))
    client_id = CONFIG["org_signin_api"]["client_id"]
    client_secret = CONFIG["org_signin_api"]["client_secret"]
    key = client_secret + client_id + ts
    hash_object = hashlib.sha256(key.encode())
    hmac = hash_object.hexdigest()

    headers = {
        'client-id': client_id,
        'ts': ts,
        'hmac': hmac
    }

    try:
        response = requests.request("GET", url, headers=headers, data=payload, files=files)
        if response.status_code != 200:
            return None

        return response.json()

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {"status": "error", "response": Errors.error('err_1201')+"[#1502]"}


def get_users(str_value, user_type):
    try:
        if not str_value:
            return {"status": "error", "response": "No value provided"}, 400

        query = {"mobile_no": str_value}
        fields = {}
        if user_type == "other":
            token_data = CommonLib.getAccessToken(str_value)
            token_json_data = json.loads(token_data)
            if "token" in token_json_data:
                str_value = token_json_data["token"]
                query = {
                    "$or": [
                        {"vt": str_value},
                        {"user_alias": str_value},
                        {"user_id": str_value},
                    ]
                }

        response, status_code = MONGOLIB.accounts_eve(accounts_eve['collection_usr'], query, fields)
        if status_code != 200:
            return {
                "status": "error",
                "response ": "Not Found",
            }, status_code

        if (
            response["response"]
            and isinstance(response["response"], list)
            and len(response["response"]) > 0
        ):
            userData = response["response"]

            objList = []
            users_details = []

            for user in userData:
                objList.append(user["digilockerid"])
                users_details.append(
                    {
                        "digilockerid": user["digilockerid"],
                        "user_type": user["user_type"],
                        "user_id": user["user_id"],
                        "org_id_exists": user.get("org_id", ""),
                    }
                )

            profile_data = {}
            profiles = get_profilename(objList)

            for v in profiles:
                digilockerid = v["digilockerid"]
                profile_data[digilockerid] = {"name": v["name"]}

            mynw_grouping = {}
            for v1 in users_details:
                lockerid = v1["digilockerid"]
                if lockerid in mynw_grouping:
                    mynw_grouping[lockerid] = v1
                else:
                    mynw_grouping[lockerid] = v1
                    mynw_grouping[lockerid]["name"] = profile_data.get(lockerid).get(
                        "name", v1["user_id"]
                    )

            final_data = list(mynw_grouping.values())
            return {"status": "success", "response": final_data}, 200
        else:
            return {"status": "error", "response": "No user data found"}, 404

    except Exception as e:
        VALIDATIONS.log_exception(e)
        return {"status": "error", "response": Errors.error('err_1201')+"[#1503]"}, 500


def get_profilename(objList):
    query = {"digilockerid": {"$in": objList}}
    fields = {}
    response = MONGOLIB.accounts_eve(accounts_eve['collection_usr_profile'], query, fields)
    userData = response[0]
    if userData and "response" in userData and len(userData["response"]) >= 1:
        data = []
        for profile in userData["response"]:
            data.append(
                {
                    "digilockerid": profile.get("digilockerid", ""),
                    "name": profile.get("name", ""),
                }
            )
        return data

    return []


def get_user_name(digilockerid):
    data = {"digilockerid": digilockerid}
    resp, status_code = MONGOLIB.accounts_eve(accounts_eve['collection_usr_profile'], data, {"name": 1})
    name = None
    if status_code == 200 and resp["status"] == "success":
        user_info = resp["response"][0]
        if "name" in user_info:
            name = user_info["name"]
    return name