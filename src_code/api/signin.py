import hashlib, random, uuid, bcrypt, requests, time, os, re
from datetime import datetime, timezone
from flask import request, Blueprint, g
from lib.constants import *
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.drivejwt import DriveJwt
from api.org_activity import activity_insert
from lib.commonlib import CommonLib
# from lib.redislib import RedisLib
from lib.secretsmanager import SecretManager
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash

MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
# REDISLIB = RedisLib()

logs_queue = "org_sighin_user_"
bp = Blueprint("signin", __name__)
logarray = {}
CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())


try:
    CONFIG["JWT_SECRET"] = secrets.get("aes_secret", os.getenv("JWT_SECRET"))
except Exception as s:
    CONFIG["JWT_SECRET"] = os.getenv("JWT_SECRET")  # for local


@bp.before_request
def validate():
    """
    JWT Authentication
    """
    try:
        if request.method == "OPTIONS":
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = "healthcheck, get_multiuser_clients"
        if (
            request.path.split("/")[1] in bypass_urls
            or request.path.split("/")[-1] in bypass_urls
        ):
            return
        org_bypass_urls = "create_org_user"
        g.endpoint = request.path
        if request.path.split("/")[-1] == "get_user_request":
            res, status_code = CommonLib().validation_rules(request, True)
            if status_code != 200:
                return res, status_code
            logarray.update(
                {ENDPOINT: g.endpoint, REQUEST: {"user": res[0], "client_id": res[1]}}
            )
            return

        jwtlib = DriveJwt(request, CONFIG)
        if request.path.split("/")[-1] in org_bypass_urls:
            jwtres, status_code = jwtlib.jwt_login()
        else:
            jwtres, status_code = jwtlib.jwt_login_org()
        if status_code != 200:
            return jwtres, status_code
        g.path = jwtres
        g.jwt_token = jwtlib.jwt_token
        g.did = jwtlib.device_security_id
        g.digilockerid = jwtlib.digilockerid
        g.org_id = jwtlib.org_id
        g.role = jwtlib.user_role
        g.org_access_rules = jwtlib.org_access_rules
        g.org_user_details = jwtlib.org_user_details
        g.dept_details = jwtlib.dept_details
        g.sec_details = jwtlib.sec_details
        g.consent_time = ""
        consent_bypass_urls = (
            "get_details",
            "get_access_rules",
            "get_users",
            "get_authorization_letter",
            "get_access_rules",
            "update_avatar",
            "get_avatar",
            "send_mobile_otp",
            "verify_mobile_otp",
            "send_email_otp",
            "verify_email_otp",
            "get_user_request",
            "get_user_requests",
            "update_cin_profile",
            "update_icai_profile",
            "update_udyam_profile",
            "esign_consent_get",
        )
        if (
            request.path.split("/")[1] not in consent_bypass_urls
            and request.path.split("/")[-1] not in consent_bypass_urls
        ):
            consent_status, consent_code = esign_consent_get()
            if (
                consent_code != 200
                or consent_status.get(STATUS) != SUCCESS
                or not consent_status.get("consent_time")
            ):
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            try:
                datetime.datetime.strptime(
                    consent_status.get("consent_time", ""), D_FORMAT
                )
            except Exception:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_194")}, 400
            g.consent_time = consent_status.get("consent_time")

        logarray.update({"org_id": g.org_id, "digilockerid": g.digilockerid})
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401


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
            users, status_code = get_users(aadhar, 'other')
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
    for user in users["response"]:
        if "org_id" in user and user["org_id"]:
            for org_id in user["org_id"]:
                is_valid_organization = check_for_organization(user["digilockerid"], org_id)
                if is_valid_organization is not None:
                    data_as_per_org = user.copy()
                    data_as_per_org["digilockerid"] = CommonLib.aes_encryption(user["digilockerid"])
                    data_as_per_org["user_id"] = CommonLib.aes_encryption(user["user_id"])
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
    url = CONFIG["org_signin_api"]["url"] + "/org/get_access_rules"
    ts = str(int(time.time()))
    hmac = hashlib.sha256(f"{client_secret}{client_id}{ts}".encode()).hexdigest()
    
    headers = {"client_id": client_id, "ts": ts, "hmac": hmac}
    params = {"digilockerid": lockerid, "org_id": org_id}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code != 200:
            return {"status": "error", "response": "Record not found", "code": 404}

        return {"status": "success", "response": response.json(), "code": 200}

    except Exception as e:
        return {"status": "error", "response": str(e)}

# Function to get users based on str_value and user_type
def get_users(str_value, user_type):
    if not str_value:
        return {"status": "error", "response": "No value provided"}, 400

    query = {"mobile_no": str_value}
    fields = {}

    if user_type == 'other':
        token_data = CommonLib.getAccessToken(str_value)
        token_json_data = json.loads(token_data)
        if 'token' in token_json_data:
            str_value = token_json_data['token']
        query = {"$or": [{"vt": str_value}, {"user_alias": str_value}, {"user_id": str_value}]}

    userData = MONGOLIB.accounts_eve("users", query, fields)

    if userData and 'documents' in userData and len(userData['documents']) >= 1:
        objList = []
        users_details = []

        for user in userData['documents']:
            objList.append(user['digilockerid'])
            users_details.append({
                'digilockerid': user['digilockerid'],
                'user_type': user['user_type'],
                'user_id': user['user_id'],
                'org_id_exists': user.get('org_id', False)
            })

        profile_data = {}
        profiles = get_profilename(objList)

        for v in profiles:
            digilockerid = v['digilockerid']
            profile_data[digilockerid] = {'name': v['name']}

        mynw_grouping = {}
        for v1 in users_details:
            lockerid = v1['digilockerid']
            if lockerid in mynw_grouping:
                mynw_grouping[lockerid] = v1
            else:
                mynw_grouping[lockerid] = v1
                mynw_grouping[lockerid]['name'] = profile_data.get(lockerid, {}).get('name', v1['user_id'])

        final_data = list(mynw_grouping.values())
    else:
        final_data = []

    return final_data, 200

# Function to get profile names based on objList
def get_profilename(objList):
    query = {"digilockerid": {"$in": objList}}
    fields = {}
    userData = MONGOLIB.accounts_eve("users_profile", query, fields)

    if userData and 'documents' in userData and len(userData['documents']) >= 1:
        data = []
        for profile in userData['documents']:
            data.append({
                'digilockerid': profile.get('digilockerid', ''),
                'name': profile.get('name', '')
            })
        return data
    return []
