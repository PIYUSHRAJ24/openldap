from lib.constants import *
import requests
import json
from flask import url_for, g
from lib.mongolib import MongoLib
import xmltodict

from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
rmq = RabbitMQTaskClientLogstash()

from lib.redislib import RedisLib
rs = RedisLib()
MONGOLIB = MongoLib()
class ProfileModel:
    def __init__(self):
        pass

    '''Below method will validate token and return lockerid'''
    def getKYCXMLFromAPI(self, uid_token_hash, user, rmq_queue):
        log_data = {'step':'get_xml_data', 'digilockerid':user, 'token_hash':uid_token_hash}
        try:
            url = os.getenv('uidai_get_data_url')
            payload = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><PullDocRequest xmlns:ns2=\"http://tempuri.org/\" ver=\"1.0\" ts=\"2022-02-01T09:03:08+05:30\" txn=\"562ae0e699e2521ac4bd55f5ca61e553\" orgId=\"in.gov.uidai\" keyhash=\"990f29d904518604243d7242b789477b2f6b475105e399a11a963235ed74b29d\" metadata=\"N\" format=\"xml\"><DocDetails><URI>in.gov.uidai-ADHAR-" + uid_token_hash + "</URI><DigiLockerId>sample00-1aa1-11a1-10a0-digilockerid</DigiLockerId></DocDetails></PullDocRequest>"
            headers = {
                'Content-Type': 'application/xml'
            }
            response = requests.request("POST", url, headers=headers, data=payload)
            tree = xmltodict.parse(response.text, attr_prefix='')
            if 'ResponseStatus' in tree.get('xml'):
                if tree.get('xml').get('ResponseStatus').get('StatusCode') == '1':
                    data = tree.get('xml').get('DocDetails').get('DataContent')
                    if data is None or len(data) < 1000:
                        log_data['status'] = 'error'
                        log_data['error_description'] = 'kyc data not found-1'
                        rmq.log_stash_logeer(log_data, rmq_queue)
                        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_183")}, 404
                    
                    return {STATUS: SUCCESS, 'data': data}, 200
            else:
                log_data['status'] = 'error'
                log_data['error_description'] = 'kyc data not found-2'
                rmq.log_stash_logeer(log_data, rmq_queue)
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_183")}, 404

        except Exception as e:
            log_data['status'] = 'error'
            log_data['error_description'] = str(e)
            rmq.log_stash_logeer(log_data, rmq_queue)
            return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111")}, 400

