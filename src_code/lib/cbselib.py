import os, json
from lib.redislib import RedisLib
import hashlib
import pymongo
from datetime import datetime

class Cbse:
    def __init__(self, mongo_uri, db_name):
        self.rs = RedisLib()
        self.mongo_uri = mongo_uri
        self.db_name = db_name

    def get_connection(self):
        self.conn = pymongo.MongoClient(self.mongo_uri)
        self.db = self.conn[self.db_name]


    def find_cbse(self, collection_name, query, limit=0, projection=None, sort=None, skip=0):
        self.get_connection()
        collection = self.db[collection_name]
        
        if sort is None:
            data = collection.find(query, projection)
        else:
            data = collection.find(query, projection).sort(sort[0], sort[1]).limit(limit).skip(skip)

        return data 
    
    '''This function will return list of students from db..store in redis also'''
    '''This API is temporary till CBSE downloads all the records'''
    
    def schoolcode_exists(self, query, school_code, batch):
        try:
            from_redis = self.rs.get(key = 'school_code_'+school_code+'_'+batch) #school_code_10001_X, school_code_10001_XII
            
            if from_redis is not None:
                return 200, json.loads(from_redis)
            res = self.find_cbse('cbse_temp_data', query, limit=0, projection={'_id': 0, "roll_no": 1, "full_name": 1, "pin": 1})
            # return 200, [doc for doc in res]            
            resp = []
            for k in res:
                resp.append(k)
            
            if len(resp)>0:
                self.rs.set(key = 'school_code_'+school_code+'_'+batch, value = json.dumps(resp), ex=86400)
            return 200, resp
        except Exception as e:
            return 400, []    
            
    def CheckAuthentication(self, client_id, hmac, school_code, ts):
        try:
            if client_id is None or hmac is None or ts is None or school_code is None:
                return 401, {'status': 'error', 'error_description': 'Unauthorised Access'}
                
            #get hmac from data coming from client side
            key_received = hmac
            
            #creating hmac on server side stored secret
            secret='747ae79468e5196e4f1f'
            plain_text_key_created = secret + client_id + school_code +ts
            
            key_created = hashlib.sha256(plain_text_key_created.encode()).hexdigest()
            
            if key_received == key_created:
                return 200, {'status': 'suceess'}
            else:
                return 401, {'status': 'error', 'error_description': 'Unauthorised Access'}
        except Exception as e:
            return 400, {"status": "error", "error_description": str(e)}

    def ins(self):
        try:
            self.get_connection()
            collection = self.db['cbse_temp_data']
            d1 = {
                "temp_id" : "b6f38320-fb94-401c-b3f4-f7b299bbdf31",
                "full_name" : "Abhijeet Anand",
                "pin" : "111111",
                "gender" : "M",
                "school_code" : "50095",
                "roll_no" : "7126766",
                "class" : "X",
                "yop" : "2024",
                "dob" : datetime(1998, 12, 22)
            }
            
            d2 = {
                "temp_id" : "b6f38320-fb94-401c-b3f4-f7b299bbdf32",
                "full_name" : "Chitranjan Kumar Ranjan",
                "pin" : "111111",
                "gender" : "M",
                "school_code" : "50002",
                "roll_no" : "1204443",
                "class" : "XII",
                "yop" : "2024"
            }
            
            d3 = {
                "temp_id" : "030359b9-9f3f-467b-814d-f6ec49b1d450",
                "full_name" : "Barisha Chatterjee",
                "pin" : "111113",
                "gender" : "F",
                "school_code" : "50097",
                "roll_no" : "7126867",
                "class" : "X",
                "yop" : "2024",
                "dob" : datetime(2013, 11, 18) #yyyy-mm-dd
            }



            d4 = {
                "temp_id" : "7b417d49-8577-441c-8d67-a8cf285a83c2",
                "full_name" : "Anjali Kumari",
                "pin" : "111114",
                "gender" : "F",
                "school_code" : "50098",
                "roll_no" : "7126868",
                "class" : "X",
                "yop" : "2024",
                "dob" : datetime(2016, 1, 18) #yyyy-mm-dd
            }



            d5 = {
            "temp_id" : "e6a6c520-ebf5-4f38-837e-920e0701d954",
            "full_name" : "Bishamber Singh",
            "pin" : "111115",
            "gender" : "M",
            "school_code" : "50099",
            "roll_no" : "7126869",
            "class" : "X",
            "yop" : "2024",
            "dob" : datetime(1959, 8, 1) #yyyy-mm-dd
            }
            
            d6 = {
                "temp_id" : "3316c272-569c-4467-815c-07ad5630785a",
                "full_name" : "Anjali Kumari",
                "pin" : "111112",
                "gender" : "F",
                "school_code" : "50096",
                "roll_no" : "7126866",
                "class" : "X",
                "yop" : "2024",
                "dob" : datetime(1990, 9, 23) #yyyy-mm-dd
}
            
            collection.insert_one(d1)
            collection.insert_one(d2)
            collection.insert_one(d3)
            collection.insert_one(d4)
            collection.insert_one(d5)
            collection.insert_one(d6)

            return {'s':'s'} 
        except Exception as e:
            return {'status':'error', 'err':str(e)}

    def ddd(self, roll):
        try:
            if not roll:
                return {'status':'error', 'err':'give roll'}
                
            self.get_connection()
            collection = self.db['cbse_temp_data']
            filter1 = {'roll_no':roll}
            data = collection.find_one_and_delete(filter1)
            return {'s':'s'} 
        except Exception as e:
            return {'status':'error', 'err':str(e)}
