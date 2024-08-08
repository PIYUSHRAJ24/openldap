from datetime import datetime
import hashlib
from elasticsearch import Elasticsearch
from lib.constants import *
from flask import g

es_config = CONFIG['elasticsearch']
host = es_config["es_host"]#[:-1]+':443'
username = es_config["es_user"]
password = es_config["es_pass"]

ENTITY_INDEX = 'entity_details_'+APP_ENVIRONMENT.lower() if APP_ENVIRONMENT != 'PROD' else 'entity_details'


class ElasticLib:
    def __init__(self):
        self.es = Elasticsearch(host, http_auth=(username, password))

    def search(self, index_name: str, orgid='', date: str = '*'):
        query = {"bool": {"must": [{ "match": {"org_id": orgid} }]}}
        if date != '*':
            query['bool']['must'].append({ "match": {"dated": date} })
        search_parameter = {
            "query": { **query },
            "fields":
            [
                "doc_type_id",
                "count"
            ],
            "_source": False
        }
        try:
            res = self.es.search(index=index_name, body=search_parameter, request_timeout=30, timeout='30s')
            details = {'doc_count': {}}
            total = 0
            for hit in res['hits']['hits']:
                doc_type_id = hit['fields']['doc_type_id'][0]
                count = hit['fields']['count'][0]
                details['doc_count'][doc_type_id] = count
                total += count
            response = {STATUS: SUCCESS, 'org_id': orgid, 'success_pull_count': int(total), **details}
            return response, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: 'Exception:ElasticLib:search:: ' + str(e)}, 500

    def add_tokens(self, meta_data):
        self.es.index(index=es_config['es_index'], id=meta_data['file_id'], document=meta_data)
        return 'Done'
    
    def search_documents(self, index, token):
        query = {"query": {"match": {"token": token}}}
        result = self.es.search(index=index, body=query)
        return result['hits']

    def search_cin(self,query):
        '''
        Build By Puja Arkwanshi
        Release Date 28-06-2023
        TaskId  #79236
        Patch Description : this functionality will search CIN/Udyam or PAN from Entity details index as a full string match.
        '''
        try:
            query = {"query":{
                "match": {
                    "cin": {
                        "query": query,
                        "operator": "and"
                        }
                    }
                }
            }
            response = self.es.search(index=ENTITY_INDEX, body=query)
            datas = response['hits']
            org_details = []
            unique_ids = set()
            for hit in datas["hits"]:
                c_identifier = hit.get("_source", {}).get("cin")
                org_id = hit.get("_source", {}).get("org_id")
                if org_id != g.org_id and c_identifier and c_identifier not in unique_ids:
                    unique_ids.add(c_identifier)
                    org_details.append({
                        "org_id": org_id,
                        "c_identifier": c_identifier,
                        "org_name": hit.get("_source", {}).get("name")
                    })
            return org_details


        except Exception as e :
            return {STATUS:"error",RESPONSE:str(e)}

    def search_entity(self, query):
        '''
        Build By Puja Arkwanshi
        Release Date 20-06-2023
        TaskId  #79236
        Patch Description : this functionality will search Entity details and serve as suggestive output,
        will also work if the full name or details id entered.
        modified_on 28-06-2023
        modified by, @PujaArkvanshi, Abhilash
        Modiled the search type to suggestive indexing build over elastic index.
        '''
        try:
            search_query = {"suggest":{
                "suggestions":{
                    "prefix": query,
                    "completion": {
                        "field": "suggest",
                        "fuzzy": {
                            "fuzziness": 1
                            }
                        }
                    }
                }
            }
            response = self.es.search(index=ENTITY_INDEX, body=search_query)
            suggestions = response['suggest']['suggestions'][0]['options']
            org_details = []
            unique_ids = set()
            for suggestion in suggestions:
                c_identifier = suggestion.get("_source", {}).get("cin")
                org_id = suggestion.get("_source", {}).get("org_id")
                if org_id != g.org_id and c_identifier and c_identifier not in unique_ids:
                    unique_ids.add(c_identifier)
                    org_details.append({
                        "org_id": org_id,
                        "c_identifier": c_identifier,
                        "org_name": suggestion.get("_source", {}).get("name")
                    })
            if len(org_details) == 0:
                return self.search_cin(query)
            return org_details

        except Exception as e:
            return {STATUS:"error",'results': []}
        
    def send_signup_stats(self, data):
        try:
            data.update({
                'stats_type': 'org_cin_update',
                'ts': datetime.now().isoformat(),
                'report_date': datetime.now().strftime('%Y-%m-%d')
            })
            doc_id = hashlib.md5(data['org_id'].encode()).hexdigest()
            return self.es.index(index=ENTITY_INDEX, id=doc_id, document=data)
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: str(e)}
