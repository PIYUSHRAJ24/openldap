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
                "users", query, fields, limit=1
            )
            if status_code != 200:
                return {"status": "error", "response ": f"{mobile_no} Not Found" }, status_code

            users = []
            if responce["status"] == "success":
                user_info = responce["response"][0]
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
        else :
            filtered_data = filter_data(usr)
            
    except Exception as e:
        return {
            "status": "error",
            "response": f"An error occurred: {str(e)}",
        }, 500

    return filtered_data, 200


# Function to filter user data
def filter_data(users):
    filtered_data = []
    client_secret = CONFIG["org_signin_api"]["client_secret"]

    for user in users["response"]:
        if "org_id_exists" in user and user["org_id_exists"]:
            for org_id in user["org_id_exists"]:

                is_valid_organization = check_for_organization(
                    user["digilockerid"], org_id
                )
                if is_valid_organization is not None:
                    data_as_per_org = user.copy()
                    data_as_per_org["digilockerid"] = CommonLib.aes_encryption_v3(
                        user["digilockerid"], client_secret
                    )

                    data_as_per_org["user_id"] = CommonLib.aes_encryption_v3(
                        user["user_id"], client_secret
                    )

                    data_as_per_org["orgs"] = [is_valid_organization]
                    if "org_id" in data_as_per_org:
                        del data_as_per_org["org_id"]
                    filtered_data.append(data_as_per_org)
                    # if not any(
                    #     d["digilockerid"] == data_as_per_org["digilockerid"]
                    #     for d in filtered_data
                    # ):
                        # filtered_data.append(data_as_per_org)

    if filtered_data:
        return {"status": "success", "data": filtered_data}
    else:
        unique_mobile_numbers = {user.get("mobile_no", "") for user in users}
        return {
            "status": "success",
            "data": list(unique_mobile_numbers),
        }


# Function to check organization details
def check_for_organization(lockerid, org_id):
    res = get_org_details_based_on_lockerid(lockerid, org_id)
    # res = {
    #     "status": "success",
    #     "response": [
    #         {
    #             "access_id": "cd111bc3651bb6bc817116eb38d9e3c5",
    #             "designation": "director",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "f62b0e41-342d-4f13-a34f-22f7b7d2d35a",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-02-05T10:39:51.959000Z",
    #         },
    #         {
    #             "access_id": "ec60fac8fb5ae1c3c0fc155f52670e16",
    #             "designation": "director",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "N",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-06-07T13:28:08.829000Z",
    #         },
    #         {
    #             "access_id": "09cf6262136d538cf672ad920efc3c51",
    #             "dept_id": "58cac91f93f251681fb7f56699d70c8b",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-29T15:31:13.600000Z",
    #         },
    #         {
    #             "access_id": "be09083a951c339bb78e1fc08266b408",
    #             "dept_id": "9564913c0fd37ed5148d16f5788d0e99",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-29T15:31:16.326000Z",
    #         },
    #         {
    #             "access_id": "f91ff73c7db23c0757a40c73d8530f71",
    #             "dept_id": "d7d2a46f95e26c001daaadf7f40612ea",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-29T15:53:01.549000Z",
    #         },
    #         {
    #             "access_id": "3963681e252904f9722631825c0538a1",
    #             "dept_id": "73de10b1afaaf6baf158622c19840faf",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-29T17:07:59.992000Z",
    #         },
    #         {
    #             "access_id": "c547d4d04453b3273daa93c7a52fa014",
    #             "dept_id": "fcee10e260817ad6777f09dfcde076fb",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-29T17:08:04.661000Z",
    #         },
    #         {
    #             "access_id": "b7227b8ed2d60476b9b2750060456751",
    #             "dept_id": "f6c36a89c17e43ad35f69b06a21484ab",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "f62b0e41-342d-4f13-a34f-22f7b7d2d35a",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-05-31T09:50:49.384000Z",
    #         },
    #         {
    #             "access_id": "0b5e2447f7cb7c39800b9847ba1059cd",
    #             "dept_id": "fcee10e260817ad6777f09dfcde076fb",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "sec_id": "9d26be25aa4fc9133e24255361120aea",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-06-03T15:33:59.332000Z",
    #         },
    #         {
    #             "access_id": "0c1960d9622ce516ff9482e08d77da7a",
    #             "dept_id": "fcee10e260817ad6777f09dfcde076fb",
    #             "digilockerid": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "is_active": "Y",
    #             "org_id": "697b41cb-07b1-4be4-935b-76572dbd9476",
    #             "org_name": "GKS ACCOUNTANTS PRIVATE LIMITED ",
    #             "rule_desc": "Has full access to Digilocker Organization Account.",
    #             "rule_name": "admin",
    #             "sec_id": "9d26be25aa4fc9133e24255361120aea",
    #             "updated_by": "dc5d4ce6-fcc4-4adf-bd90-b668beb75269",
    #             "updated_on": "2024-06-03T15:33:47.857000Z",
    #         },
    #     ],
    # }

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

    # url = CONFIG["org_signin_api"]["url"] + "/org/get_access_rules"
    url = "https://dl-org-api.dl6.in/org/get_access_rules"
    headers = {
        "device-security-id": g.did,
        "Authorization": "Bearer " + g.jwt_token,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    params = {"digilockerid": lockerid, "org_id": org_id}

    try:
        response = requests.request("GET", url, headers=headers, data=params)
        if response.status_code != 200:
            return {"status": "error", "response": response.json(), "code": 404}

        return {"status": "success", "response": response.json(), "code": 200}

    except Exception as e:
        return {"status": "error", "response": str(e)}


def get_users(str_value, user_type):
    try:
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

        # str_value = "d31642f4-ec78-5fcc-a967-bbc6db911360"
        # query = {
        #     "$or": [
        #         {"vt": str_value},
        #         {"user_alias": str_value},
        #         {"user_id": str_value},
        #     ]
        # }

        response, status_code = MONGOLIB.accounts_eve("users", query, fields)
        if status_code != 200:
            return {"status": "error", "response ": f"{str_value} Not Found" }, status_code

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
        return {"status": "error", "response": str(e)}, 500


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


def get_user_name(digilockerid):
    data = {"digilockerid": digilockerid}
    resp, status_code = MONGOLIB.accounts_eve("users_profile", data, {"name": 1})
    name = None
    if status_code == 200 and resp["status"] == "success":
        user_info = resp["response"][0]
        if "name" in user_info:
            name = user_info["name"]
    return name
