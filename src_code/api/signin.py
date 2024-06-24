import base64
import hashlib
import re, time, requests
from datetime import datetime, timezone
from flask import request, Blueprint, g
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
        # g.role = jwtlib.user_role
        # g.org_access_rules = jwtlib.org_access_rules
        # g.org_user_details = jwtlib.org_user_details
        # g.user_rules = jwtlib.user_rules
        # g.org_access_functions = jwtlib.org_access_functions
        # g.user_departments = jwtlib.user_departments
        # g.org_access_functions = jwtlib.org_access_functions
        # g.org_ds_fn_roles = jwtlib.org_ds_fn_roles
        # g.dept_details = jwtlib.dept_details
        # g.sec_details = jwtlib.sec_details
        logarray.update({"org_id": g.org_id, "digilockerid": g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


@bp.route("/", methods=["GET", "POST"])
def healthcheck():
    return {STATUS: SUCCESS}

@bp.route('/user_list', methods=['POST'])
def list_department():
    try:
        
        query = {"mobile_no": '9389856738'}
        fields = {}
        resp, status_code = MONGOLIB.accounts_eve("users", query, fields, limit=1)

        
        if status_code != 200:
            return resp, status_code
        
        data = []

        for d in resp[RESPONSE]:
            
                data.append(d)

        return {STATUS: SUCCESS, RESPONSE: data}, 200
    except Exception as e:
        res = {STATUS: ERROR, ERROR_DES: "users: " + str(e)}
        return res, 400

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
            users, status_code = MONGOLIB.accounts_eve("users", query, fields, limit=1)

        if status_code != 200:
            return users, status_code

        # Filter the user data
        filtered_data = filter_data(users)

    except Exception as e:
        return {
            "status": "error",
            "response": f"An error occurred: {str(e)}",
        }, 500

    return {"status": "success", "response": filtered_data}, 200


# Function to filter user data
def filter_data(users):
    filtered_data = []
    for user in users:
        if "org_id_exists" in user and user["org_id_exists"]:
            for org_id in user["org_id_exists"]:
                is_valid_organization = check_for_organization(
                    user["digilockerid"], org_id
                )
                if is_valid_organization is not None:
                    data_as_per_org = user.copy()
                    data_as_per_org["digilockerid"] = CommonLib.aes_encryption(
                        user["digilockerid"]
                    )
                    data_as_per_org["user_id"] = CommonLib.aes_encryption(
                        user["user_id"]
                    )
                    data_as_per_org["orgs"] = [is_valid_organization]
                    del data_as_per_org["org_id"]
                    filtered_data.append(data_as_per_org)

    if filtered_data:
        unique_mobile_numbers = set(user["mobile_no"] for user in users["response"])
        return {
            "data": filtered_data,
            "response": list(unique_mobile_numbers),
        }
    else:
        return []


# Function to check organization details
def check_for_organization(lockerid, org_id):
    res = get_org_details_based_on_lockerid(lockerid, org_id)
    if res["status"] == "success" and res["response"]:
        if res["response"][0] and res["response"][0]["is_active"] == "Y":
            data = res["response"][0]
            return {
                "org_id": data["org_id"],
                "org_name": data.get("org_name", data["org_id"]),
            }

    return None


# Function to get organization details based on locker ID and org ID
def get_org_details_based_on_lockerid(lockerid=None, org_id=None):
    client_secret = CONFIG["org_signin_api"]["client_secret"]
    client_id = CONFIG["org_signin_api"]["client_id"]
    url = (
        CONFIG["org_signin_api"]["url"]
        + "org/get_access_rules?digilockerid="
        + lockerid
        + "&org_id="
        + org_id
    )
    # url = CONFIG["org_signin_api"]["url"] + "/org/get_access_rules"
    ts = str(int(time.time()))
    plain_text = client_secret + client_id + ts
    hmac = hashlib.sha256(plain_text.encode()).hexdigest()

    headers = {
    'device-security-id': g.did,
    'client_id': client_id,
    'ts': ts,
    'hmac': hmac,
    'Authorization': 'Bearer '+ g.jwt_token,
    'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # headers = {
    # 'client_id': client_id,
    # 'ts': ts,
    # 'hmac': hmac,
    # }


    params = {"digilockerid": lockerid, "org_id": org_id}

    try:
        response = requests.request("GET", url, headers=headers, data=params)
        # print(response.json())
        # print("========cdddddddddddddddd==========")
        # exit()

        if response.status_code != 200:
            return {"status": "error", "response": response.json(), "code": 404}

        return {"status": "success", "response": response.json(), "code": 200}

    except Exception as e:
        return {"status": "error", "response": str(e)}


# Function to get users based on str_value and user_type
def get_users(str_value, user_type):
    if not str_value:
        return {"status": "error", "response": "No value provided"}, 400

    query = {"mobile_no": str_value}
    fields = {}

    # if user_type == 'other':
    #     token_data = CommonLib.getAccessToken(str_value)
    #     token_json_data = json.loads(token_data)
    #     if 'token' in token_json_data:
    #         str_value = token_json_data['token']
    #     query = {"$or": [{"vt": str_value}, {"user_alias": str_value}, {"user_id": str_value}]}

    str_value = "d31642f4-ec78-5fcc-a967-bbc6db911360"
    query = {
        "$or": [{"vt": str_value}, {"user_alias": str_value}, {"user_id": str_value}]
    }

    response = MONGOLIB.accounts_eve("users", query, fields)
    userData = response[0]
    if userData and "response" in userData and len(userData["response"]) > 0:
        objList = []
        users_details = []
        for user in userData["response"]:
            objList.append(user["digilockerid"])
            users_details.append(
                {
                    "digilockerid": user["digilockerid"],
                    "user_type": user["user_type"],
                    "user_id": user["user_id"],
                    "org_id_exists": user.get("org_id", False),
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
                mynw_grouping[lockerid]["name"] = profile_data.get(lockerid, {}).get(
                    "name", v1["user_id"]
                )

        final_data = list(mynw_grouping.values())
    else:
        final_data = []

    return final_data, 200


# Function to get profile names based on objList
def get_profilename(objList):
    query = {"digilockerid": {"$in": objList}}
    fields = {}
    response = MONGOLIB.accounts_eve("users_profile", query, fields)
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
