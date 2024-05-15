import redis
from rediscluster import RedisCluster
from lib.constants import CONFIG

redis_config= CONFIG['redis']
RESTRICT_TIME = 600
RESTRICT_COUNT = 5


class RedisLib:
    def __init__(self):
        try:
            if int(redis_config["redis_cluster_enabled"]) == 1:
                startup_nodes = [{"host": redis_config["redis_cluster_node_1_host"],
                                  "port": redis_config["redis_cluster_node_1_port"]},
                                 {"host": redis_config["redis_cluster_node_2_host"],
                                  "port": redis_config["redis_cluster_node_2_port"]},
                                 {"host": redis_config["redis_cluster_node_3_host"],
                                  "port": redis_config["redis_cluster_node_3_port"]},
                                 {"host": redis_config["redis_cluster_node_4_host"],
                                  "port": redis_config["redis_cluster_node_4_port"]},
                                 {"host": redis_config["redis_cluster_node_5_host"],
                                  "port": redis_config["redis_cluster_node_5_port"]},
                                 {"host": redis_config["redis_cluster_node_6_host"],
                                  "port": redis_config["redis_cluster_node_6_port"]}]
                self.RedisConn = RedisCluster(startup_nodes=startup_nodes, decode_responses=True,
                                              password=redis_config["redis_cluster_password"])
            elif int(redis_config["redis_enabled"]) == 1:
                self.RedisConn = redis.Redis(password=redis_config["redis_password"], host=redis_config["redis_host"],
                                             port=int(redis_config["redis_port"]), db=0, charset="utf-8", decode_responses=True)
                # charset="utf-8", decode_responses=True added in order to return as str instead of byte.
        except Exception as e:
            print(e)
            self.RedisConn = False

    def is_redis_available(self):
        try:
            if int(redis_config["redis_cluster_enabled"]) == 1 or int(redis_config["redis_enabled"]) == 1:
                return True
            return False
        except Exception as e:
            return False

    def get(self, key):
        if self.is_redis_available():
            return self.RedisConn.get(key)
        return False

    def remove(self, key):
        if self.is_redis_available():
            return self.RedisConn.delete(key)
        return False

    def incr(self, key):
        if self.is_redis_available():
            return self.RedisConn.incr(key)
        return False

    def expire(self, key, time):
        if self.is_redis_available():
            return self.RedisConn.expire(key, time)
        return False

    def setUnlimited(self, key, value):
        if self.is_redis_available():
            return self.RedisConn.set(key, value)
        return False
    
    def set(self, key, value, ex=600):
        if self.is_redis_available():
            return self.RedisConn.set(key, value, ex)
        return False

    def scan(self, key):
        if self.is_redis_available():
            return self.RedisConn.scan_iter("*" + key + "*")
        return False

    ''' aadhaer otp'''
    def checkAttemptValidateOtp(self, Usrkey):
        key = 'b_attempt_' + Usrkey
        res = self.get(key)
        if res and int(res) >= RESTRICT_COUNT:
            return False
        else:
            self.incr(key)
            self.expire(key, RESTRICT_TIME)
            return True
    
    
    def clearRetry(self, Usrkey):
        key = 'b_retry_' + Usrkey
        return self.remove(key)
    
    def clearAttempt(self, Usrkey):
        key = 'b_attempt_' + Usrkey
        return self.remove(key)  
    
    def ttl(self, key):
        if self.is_redis_available():
            return self.RedisConn.ttl(key)
        return 0
