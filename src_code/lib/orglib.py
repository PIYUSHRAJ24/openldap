import bcrypt
import hashlib
from lib.constants import *



class OrgLib:
    def __init__(self):
        self.active = True
    
    def match_pin(self, pin, hash):
        try:
            if pin != '' and hash:
                if self.password_verify(pin, hash):
                    return {STATUS: SUCCESS}
                else:
                    return {STATUS: ERROR}   
            else:
                return {STATUS: ERROR, ERROR_DES:Errors.error('ERR_MSG_111')}
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: str(e)}

    def password_verify(self, password, hash_value):
        try:
            if not (len(hash_value) == 32 or len(hash_value.split('|')[-1]) == 60) or len(password)!=6:
                return False
            if len(hash_value) == 32:
                md5_pin = hashlib.md5(((str(password)).strip()).encode()).hexdigest()
                return md5_pin == hash_value
            else:
                hash_value = hash_value.split('|')[1]
                compare = bcrypt.checkpw(password.encode("utf-8"), hash_value.encode("utf-8"))
                return (compare == True)
        except Exception as e:
            return False
    
    def get_hash_pwd(self, pin):
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(pin.encode('utf-8'), salt)
            return '1|'+ hashed.decode('utf-8')
        except Exception as e:
            pass
