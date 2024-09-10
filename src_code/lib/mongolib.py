from datetime import datetime, timezone
import hashlib
import json, bcrypt, re
import time
import pymongo
from requests import get, post, delete, patch
import requests
from requests.auth import HTTPBasicAuth
from lib.redislib import RedisLib
from lib.constants import *

accounts_eve = CONFIG["accounts_eve"]
org_eve = CONFIG["org_eve"]
aadhaar_uri = CONFIG["aadhaar_uri"]
ids = CONFIG["ids"]


class MongoLib:
    def __init__(self):
        self.rs = RedisLib() 

    def get_hash(self, key):
        return hashlib.md5(((str(key)).strip()).encode()).hexdigest()

    def get_hash_pwd(self, pin):
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(pin.encode("utf-8"), salt)
            return "1|" + hashed.decode("utf-8")
        except Exception as e:
            pass
    
    def devices_eve(self, locker_id, collection, query, sort={}, limit=10):
        try:
            redis_key = "devices_" + locker_id
            redis_res = self.rs.get(key=redis_key)
            if redis_res is not None:
                return json.loads(redis_res), 200
            eve_query = (
                "/"
                + collection
                + "?where="
                + json.dumps(query)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = accounts_eve["url"] + eve_query
            print(eve_url)
            get_eve_data = get(
                eve_url,
                auth=HTTPBasicAuth(accounts_eve["username"], accounts_eve["password"]),
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    data.pop("_id")
                    data.pop("_created")
                    data.pop("_updated")
                    data.pop("_links")
                    return data

                dev_data = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                redis_res = {STATUS: SUCCESS, RESPONSE: dev_data}
                self.rs.setUnlimited(key=redis_key, value=json.dumps(redis_res))
                return redis_res, 200
            return {STATUS: ERROR, ERROR_DES: "No data found"}, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:accounts_devices_eve: " + str(e),
            }, 500

    def devices_entity_lockerid_eve(
        self, locker_id, entity_id, collection, query, sort={}, limit=10
    ):
        try:
            redis_key = "devices_" + locker_id + "_" + entity_id
            redis_res = self.rs.get(key=redis_key)
            if redis_res is not None:
                return json.loads(redis_res), 200
            eve_query = (
                "/"
                + collection
                + "?where="
                + json.dumps(query)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = accounts_eve["url"] + eve_query
            get_eve_data = get(
                eve_url,
                auth=HTTPBasicAuth(accounts_eve["username"], accounts_eve["password"]),
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    data.pop("_id")
                    data.pop("_created")
                    data.pop("_updated")
                    data.pop("_links")
                    return data

                dev_data = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                redis_res = {STATUS: SUCCESS, RESPONSE: dev_data}
                self.rs.setUnlimited(key=redis_key, value=json.dumps(redis_res))
                return redis_res, 200
            return {STATUS: ERROR, ERROR_DES: "No data found"}, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:accounts_devices_eve: " + str(e),
            }, 500

    def devices_entity_eve_by_entity_id(
        self, entity_id, collection, query, sort={}, limit=10
    ):
        try:
            redis_key = "devices_" + entity_id
            redis_res = self.rs.get(key=redis_key)
            if redis_res is not None:
                return json.loads(redis_res), 200
            eve_query = (
                "/"
                + collection
                + "?where="
                + json.dumps(query)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = accounts_eve["url"] + eve_query
            get_eve_data = get(
                eve_url,
                auth=HTTPBasicAuth(accounts_eve["username"], accounts_eve["password"]),
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    data.pop("_id")
                    data.pop("_created")
                    data.pop("_updated")
                    data.pop("_links")
                    return data

                dev_data = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                redis_res = {STATUS: SUCCESS, RESPONSE: dev_data}
                self.rs.setUnlimited(key=redis_key, value=json.dumps(redis_res))
                return redis_res, 200
            return {STATUS: ERROR, ERROR_DES: "No data found"}, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:accounts_devices_eve: " + str(e),
            }, 500

    def accounts_eve(self, collection, query, projection, sort={}, limit=50):
        try:
            key = json.dumps(query).split(":")[1].replace("}", "").replace(
                '"', ""
            ) + Constants.constant("R_KEY_" + collection.upper())
            res = self.rs.get(key=key)
            if res:
                return json.loads(res), 200
            eve_query = (
                "/"
                + collection
                + "?where="
                + json.dumps(query)
                + "&projection="
                + json.dumps(projection)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = accounts_eve["url"] + eve_query
            get_eve_data = get(
                eve_url,
                auth=HTTPBasicAuth(accounts_eve["username"], accounts_eve["password"]),
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    data.pop("_id")
                    data.pop("_created")
                    data.pop("_updated")
                    data.pop("_links")
                    return data

                userdata = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                res = {STATUS: SUCCESS, RESPONSE: userdata}
                self.rs.set(key=key, value=json.dumps(res))
                return res, 200
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error("ERR_MSG_110"),
                    RESPONSE: get_eve_data.text,
                }, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:accounts_eve: " + str(e),
            }, 500

    def accounts_eve_v2(self, collection, query, projection, sort={}, limit=1):
        try:
            eve_query = (
                collection
                + "?where="
                + json.dumps(query)
                + "&projection="
                + json.dumps(projection)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = accounts_eve["url"] + eve_query

            get_eve_data = get(
                eve_url,
                auth=HTTPBasicAuth(accounts_eve["username"], accounts_eve["password"]),
            )
            eve_resp_data = json.loads(get_eve_data.content)

            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    data.pop("_id")
                    data.pop("_created")
                    data.pop("_updated")
                    data.pop("_links")
                    return data

                userdata = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                res = {STATUS: SUCCESS, RESPONSE: userdata}
                return res, 200
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error("ERR_MSG_110"),
                    RESPONSE: get_eve_data.text,
                }, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:accounts_eve: " + str(e),
            }, 400

    def org_eve(self, collection, query, projection, sort={}, limit=10):
        try:
            eve_query = (
                collection
                + "?where="
                + json.dumps(query)
                + "&projection="
                + json.dumps(projection)
                + "&max_results="
                + str(limit)
                + "&sort="
                + json.dumps(sort)
            )
            eve_url = org_eve["url"] + eve_query
            get_eve_data = get(
                eve_url, auth=HTTPBasicAuth(org_eve["username"], org_eve["password"])
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    try:
                        data.pop("_id")
                        data.pop("_created")
                        data.pop("_updated")
                        data.pop("_links")
                    except Exception:
                        pass
                    return data

                userdata = list(map(lambda x: pop(x), eve_resp_data["_items"]))
                res = {STATUS: SUCCESS, RESPONSE: userdata}
                return res, 200
            else:
                return {
                    STATUS: SUCCESS,
                    ERROR_DES: Errors.error("ERR_MSG_110"),
                    RESPONSE: get_eve_data.text,
                }, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:org_eve: " + str(e),
            }, 500
                    
    # data fetch with pagging      
    def org_eve_v2(collection_name, query, projection, sort=None, limit=10, page=1):
        try:
            limit = int(limit)
            page = int(page)

            if sort is None:
                sort = [("_id", 1)]

            eve_query = (
                collection_name
                + "?where="
                + json.dumps(query)
                + "&projection="
                + json.dumps(projection)
                + "&max_results="
                + str(limit)
                + "&page="
                + str(page)
                + "&sort="
                + json.dumps(sort)
            )

            eve_url = org_eve["url"] + eve_query
            get_eve_data = get(
                eve_url, auth=HTTPBasicAuth(org_eve["username"], org_eve["password"])
            )
            eve_resp_data = json.loads(get_eve_data.content)
            if eve_resp_data.get("_meta") and eve_resp_data["_meta"]["total"] > 0:

                def pop(data):
                    try:
                        data.pop("_id", None)
                        data.pop("_created", None)
                        data.pop("_updated", None)
                        data.pop("_links", None)
                    except Exception:
                        pass
                    return data

                userdata = list(map(pop, eve_resp_data["_items"]))
                res = {
                    STATUS: SUCCESS,
                    RESPONSE: userdata,
                    "total": eve_resp_data["_meta"]["total"],
                }
                return res, 200
            else:
                return {
                    STATUS: SUCCESS,
                    ERROR_DES: Errors.error("ERR_MSG_110"),
                    RESPONSE: "No records found",
                }, 400
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: str(e),
                RESPONSE: "An error occurred",
            }, 500
                          
    def org_eve_post(self, collection, data):
        try:
            eve_url = org_eve["url"] + collection
            response = post(
                eve_url,
                data=json.dumps(data),
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(
                    CONFIG["org_eve"]["username"], CONFIG["org_eve"]["password"]
                ),
            )
            res = json.loads(response.text)
            if response.status_code >= 200 and response.status_code < 300:
                return {STATUS: SUCCESS, MESSAGE: Messages.message("MSG_109")}, 200
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error("ERR_MSG_111"),
                    RESPONSE: res["_error"]["message"],
                }, response.status_code
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:org_eve_post: " + str(e),
            }, 400

    def org_eve_patch(self, collection, data):
        try:
            eve_url = org_eve["url"] + collection
            response = patch(
                eve_url,
                data=json.dumps(data),
                headers={"Content-Type": "application/json"},
                auth=HTTPBasicAuth(
                    CONFIG["org_eve"]["username"], CONFIG["org_eve"]["password"]
                ),
            )
            res = json.loads(response.text)
            if response.status_code >= 200 and response.status_code < 300:
                return {STATUS: SUCCESS, MESSAGE: Messages.message("MSG_109")}, 200
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error("ERR_MSG_111"),
                    RESPONSE: res["_error"]["message"],
                }, response.status_code
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:org_eve_post: " + str(e),
            }, 500

    def set_pin(self, digilockerid, pin):
        try:

            filter = {"digilockerid": digilockerid}
            update = {"pin": pin}

            res = MONGO_DB_ORG.find(MONGO_COLLECTION_ORG, filter=filter, update=update)
            # Finds a single document and updates it, returning either the original or the updated document. None... if no matching found
            if res is not None:
                return {"status": "success", "success_description": "Pin Set."}
            else:
                return {
                    "status": "error",
                    "error_description": "Login pin can not be updated!",
                }

        except Exception as e:
            return {"status": "error", "error_description": str(e)}

    # def verify_pin(self, digilockerid, pin):
    #     try:
    #         if pin and digilockerid:
    #             data = self.getUsersDataByDigilockerid(digilockerid)

    #             res = data["pin"].split("|")
    #             hash = res[1]
    #             validPin = self.match_pin(pin, hash)
    #             if validPin["status"] == "success":
    #                 return {"status": "success"}
    #         return {"status": "error"}

    #     except Exception as e:
    #         return {"status": "error", "error_description": str(e)}

    # def match_pin(self, pin, hash):
    #     try:
    #         if pin != "" and hash:
    #             if self.pin_verify(pin, hash):
    #                 return {"status": "success"}
    #             else:
    #                 return {"status": "error"}
    #         else:
    #             return {
    #                 "status": "error",
    #                 "error_description": "Some Technical Error occured.",
    #             }
    #     except Exception as e:
    #         return {"status": "error", "error_description": str(e)}

    # def pin_verify(self, pin, hash):
    #     try:
    #         if len(hash) != 60 or len(pin) != 6:
    #             return False
    #         else:
    #             compare = bcrypt.checkpw(pin.encode("utf-8"), hash.encode("utf-8"))
    #             return compare == True
    #     except Exception as e:
    #         return False

    # def pin_validation(self, pin):
    #     try:
    #         pattern = r"^\d{6}$"
    #         valid_otp = re.match(pattern, pin)
    #         if valid_otp:
    #             return 200, {"status": "success"}
    #         else:
    #             return 400, {
    #                 "status": "error",
    #                 "error_description": "Please enter valid PIN.",
    #             }
    #     except Exception as e:
    #         return 400, {
    #             "status": "error",
    #             "error_description": "Invalid pin parameter.",
    #         }

    def saveuri_aadhaar(self, digilockerid=None, uid_token=None, user=None):
        try:
            """form data to be passed in API"""
            data = {
                "issuedOn": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                "createdBy": digilockerid,
                "modifiedBy": digilockerid,
                "digilockerId": digilockerid,
                "userName": user,
                "recordFrom": "MSTL",
                "docIssueType": "Public",
                # config items
                "uri": str(aadhaar_uri["uri"]) + "-" + self.get_hash(uid_token),
                "orgId": aadhaar_uri["orgId"],
                "orgName": aadhaar_uri["orgName"],
                "docTypeId": aadhaar_uri["docTypeId"],
                "issuerId": aadhaar_uri["issuerId"],
                "docName": aadhaar_uri["docName"],
                "docId": self.get_hash(uid_token),
            }
            uri_data, code = self.common_save_uri(data, digilockerid)
            if code == 200 and uri_data.get("acknowledgeId"):
                return True
            else:
                return False
        except Exception as e:
            print(str(e))
            return False

    def common_save_uri(self, data, uid):
        try:
            """API CURL"""
            url = ids["url"] + "api/2.0/save-uri"

            ts = str(int(time.time()))
            ci_key = ids["ci_key"]
            plain_text = uid + ci_key + ts
            locker_request_token = hashlib.sha256(plain_text.encode()).hexdigest()

            payload = json.dumps(data)
            headers = {
                "ts": ts,
                "locker_request_token": locker_request_token,
                "uid": uid,
                "Content-Type": "application/json",
            }
            response = requests.request("POST", url, headers=headers, data=payload)
            return json.loads(response.text), 200

        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:common_save_uri " + str(e),
            }, 500

    @staticmethod
    def org_eve_update(collection, data, id):
        try:
            eve_url = org_eve["url"] + collection + "/" + id
            headers = {
                "Content-Type": "application/json",
            }
            response = requests.request(
                "PATCH",
                eve_url,
                headers=headers,
                data=json.dumps(data),
                auth=HTTPBasicAuth(
                    CONFIG["org_eve"]["username"], CONFIG["org_eve"]["password"]
                ),
            )
            res = json.loads(response.text)
            if response.status_code >= 200 and response.status_code < 300:
                return {STATUS: SUCCESS, MESSAGE: "update succesfully"}, 200
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error("ERR_MSG_111"),
                    RESPONSE: "MongoLib:org_eve_update: "
                    + str(res["_error"]["message"]),
                }, response.status_code
        except Exception as e:
            return {
                STATUS: ERROR,
                ERROR_DES: Errors.error("ERR_MSG_111"),
                RESPONSE: "Exception:MongoLib:org_eve_post: " + str(e),
            }, 500
