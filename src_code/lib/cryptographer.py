from lib.constants import ERROR, ERROR_DES
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from base64 import b64encode, b64decode
import hashlib

class Crypt:
    def __init__(self, sec_key) :        
        try:
            self.secret_key= sec_key
            self.precise_key=  bytearray((hashlib.md5(sec_key[:16].encode("utf-8")).hexdigest()).encode("utf-8"))
            self.iv= bytearray(sec_key[:16].encode(), "utf-8")
        except Exception as e:
            print(str(e))
            
    def enc_aes_cbc_256(self, plain_text= ""):
        try:
            new_key=bytearray((hashlib.md5(self.secret_key[:16].encode("utf-8")).hexdigest()).encode("utf-8"))
            iv = bytearray(self.secret_key[:16].encode('utf-8'))
            if plain_text is not None and ""!=plain_text:
                cipher = AES.new(new_key, AES.MODE_CBC, iv)
                padded_data = pad(plain_text.encode('utf-8'), AES.block_size)
                encrypted_data = cipher.encrypt(padded_data)
                encrypted_string = b64encode(encrypted_data).decode('utf-8')
                encrypted_string = encrypted_string.replace("\n", "")
                return 200, encrypted_string.replace("+", "---")
            else:
                return 400, {ERROR: "error", ERROR_DES: "Text must not none"}
        except Exception as e:
            return 400, {ERROR: "error", ERROR_DES: 'Exception: in Crypt.encrypt_data:: ' + str(e)}
        
    def dec_aes_cbc_256(self, encrypted_text= ""):
        try:
            if encrypted_text is not None and ""!=encrypted_text:
                filtered_cipher_text = encrypted_text.replace('---', '+')
                iv = bytearray(self.secret_key[:16].encode('utf-8'))
                new_key=bytearray((hashlib.md5(self.secret_key[:16].encode("utf-8")).hexdigest()).encode("utf-8"))
                encode_cipher = b64decode(filtered_cipher_text)
                aes_obj = AES.new(new_key, AES.MODE_CBC, iv)
                return 200, unpad(aes_obj.decrypt(encode_cipher), AES.block_size).decode('utf-8')
            else:
                return 400, {ERROR: "error", ERROR_DES: "Text must not none"}
        except Exception as e:
            return 400, {ERROR: "error", ERROR_DES: 'Exception: in Crypt.decrypt_data:: ' + str(e)}
    
    def make_sha_256_hash(self, data= ""):
        try :
            if data is not None and ""!=data:
                sha256_hash = hashlib.sha256()
                sha256_hash.update(data.encode('utf-8'))
                hash_result = sha256_hash.hexdigest()
                return 200, hash_result
            else:
                return 400, {ERROR: "error", ERROR_DES: "Text must not none"}
        except Exception as e:
            return 400, {ERROR: "error", ERROR_DES: "Text must not none:::" +str(e)}



        
    