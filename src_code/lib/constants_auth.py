import json, os, dotenv, configparser
dotenv.load_dotenv()
from datetime import datetime
CONFIG = configparser.ConfigParser()

thisfolder = os.path.dirname(os.path.abspath(__file__))
root_folder = os.path.dirname(thisfolder)
config_ini_file = os.path.join(root_folder, os.getenv('config_path', ''))
CONFIG.read(config_ini_file)


APP_ENVIRONMENT = os.getenv('environment')
DEBUG_MODE = os.getenv('debug_mode','').lower() == 'true'
# redis_ttl = os.getenv('HMAC_EXPIRY')

SUCCESS = "success"
ERROR = "error"
ERROR_DES = "error_description"
STATUS = "status"
MESSAGE = "msg"
RESPONSE = "response"
REQUEST = "request"
HEADER = "headers"
ENDPOINT = "endpoint"

D_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
CURRENT_D_FORMAT_YMDHIS = datetime.now().strftime('%Y%m%d%H%M%S')
CURRENT_D_YMDHIS = datetime.now().strftime('YmdTHMS')
redis_ttl = CONFIG['redis']['redis_key_ttl']

AADHAAR_TOKEN = 'aadhaar_token'
TRANSACTION_ID = 'transaction_id'


class Roles:
    @staticmethod
    def rule_id(code):
        rule = json.loads(CONFIG['roles'].get(code.lower()) or '{}')
        return rule
    

class Constants:
    @staticmethod
    def constant(code):
        # imports from config
        return dict(map(lambda x : (x[0].upper(), x[1]), list(CONFIG.items('constants')))).get(code, '')


class Messages:
    @staticmethod
    def message(code):
        msgs = {
            "MSG_100" : 'PAN Verification Successful.',
            "MSG_101" : 'ICAI Verification Successful.',
        }
        return msgs.get(code, '')


class Errors:
    @staticmethod
    def error(code):
        msgs = {
            "ERR_MSG_100" : 'Unsupported charecter in %s.!',
            "ERR_MSG_101" : "Invalid name",
            "ERR_MSG_102" : "Invalid original_name",
            "ERR_MSG_103" : "Invalid notification id",
            "ERR_MSG_104" : "Invalid digilockerid",
            "ERR_MSG_105" : "Invalid published date",
            "ERR_MSG_106" : "Invalid valid through date",
            "ERR_MSG_107" : "Jtoken is missing.",
            "ERR_MSG_108" : "Unauthorised Access!",
            "ERR_MSG_109" : "Invalid operation",
            "ERR_MSG_110" : "No data found.",
            "ERR_MSG_111" : "Some technical error occured",
            "ERR_MSG_112" : "Invalid message id",
            "ERR_MSG_113" : "Invalid read date",
            "ERR_MSG_114" : "No input data",
            "ERR_MSG_115" : "Invalid action taken",
            "ERR_MSG_116" : "mobile is required",
            "ERR_MSG_117" : "Aadhaar is required",
            "ERR_MSG_118" : "post all required data",
            "ERR_MSG_119" : "user is invalid or required.",
            "ERR_MSG_120" : "clientid is invalid or required.",
            "ERR_MSG_121" : "Timestamp is invalid or required.",
            "ERR_MSG_122" : "Hmac is invalid or required.",
            "ERR_MSG_123" : "orgId is invalid.",
            "ERR_MSG_124" : "org_alias is invalid.",
            "ERR_MSG_125" : "Please provide correct Organization Name",
            "ERR_MSG_126" : "Please provide valid input.",
            "ERR_MSG_127" : "rule_id is invalid.",
            "ERR_MSG_128" : "Your OTP has expired. Please click Resend OTP link below to generate a new OTP and try again.",
            "ERR_MSG_129" : "This Mobile number is not registered with DigiLocker.",
            "ERR_MSG_130" : "Please enter valid OTP.",
            "ERR_MSG_131" : "Please enter correct OTP.",
            "ERR_MSG_132" : "Please enter valid DIN.",
            "ERR_MSG_133" : "Please enter valid TXN.",
            "ERR_MSG_134" : "PAN details seems to be incorrect. Please verify and try again.",
            "ERR_MSG_1351" : "Department ID missing",
            "ERR_MSG_1361" : "Department and Section ID missing",
            "ERR_MSG_1371" : "Section ID missing",
            "ERR_MSG_1381" : "Department id invalid",
            "ERR_MSG_1391" : "Function id invalid",
            "ERR_MSG_1392" : "User Already verified",
            "ERR_MSG_1393" : "User Already deactivated",
            
            '''Aadhaar related constant'''
            
            'ERR_MSG_134' : 'Invalid Clientid provided.',
            'ERR_MSG_135' : 'Invalid Timestamp provided.',
            'ERR_MSG_136' : 'Invalid Mobile provided.',
            'ERR_MSG_137' : 'Invalid Hmac provided.',
            'ERR_MSG_138' : 'Invalid Digilockerid provided.',
            'ERR_MSG_139' : 'Invalid Pin provided.',
            'ERR_MSG_140' : 'Invalid OTP provided.',
            'ERR_MSG_141' : 'Invalid Username provided.',
            'ERR_MSG_142' : 'Invalid uid_token provided.',
            'ERR_MSG_143' : 'Pin and Confirm Pin don\'t match.',
            'ERR_MSG_144' : "Invalid Confirm pin.",
            'ERR_MSG_145' : 'Request Failed(#R408).',
            'ERR_MSG_146' : 'Please enter valid Pin.',
            "ERR_MSG_147" : "Please enter valid PAN",
            "ERR_MSG_148" : "Please enter valid CIN",
            "ERR_MSG_149" : "Please enter valid gstin name",
            "ERR_MSG_150" : "Please enter valid gstin",
            "ERR_MSG_151" : "Please provide any unique identifier %s",
            "ERR_MSG_152" : "Invalid date of incorporation provided.",
            "ERR_MSG_153" : "Invalid type.",
            "ERR_MSG_154" : "Invalid subject.",
            "ERR_MSG_155" : "Invalid document name.",
            "ERR_MSG_156" : "Please enter correct PIN.",
            "ERR_MSG_157" : "No record found using DIN.",
            "ERR_MSG_158" : "No CIN number found.",
            "ERR_MSG_159" : "DIN number is not registered with the organization .",
            "ERR_MSG_160" : "Please enter valid Udyam Number.",
            "ERR_MSG_161" : "Unauthorized access! You do not have access to this Organization.",
            "ERR_MSG_162" : "You are only allowed to add %s users."%CONFIG['roles']['max_users'],
            "ERR_MSG_163" : "The CIN you entered is already registered with us.",
            'ERR_MSG_164' : "Service is temporarily not available. Please try again after some time.",
            'ERR_MSG_165' : "An user can only be associated with %s Entities."%CONFIG['roles']['max_organizations'],
            'ERR_MSG_166' : "Account not created.",
            "ERR_MSG_167" : "The Udyam Number you entered is already registered with us.",
            "ERR_MSG_168" : "Provided CIN or Udyam Number is not valid.",
            "ERR_MSG_169" : "Invalid is_active.",
            "ERR_MSG_170" : "Invalid access_id.",
            "ERR_MSG_171" : "Invalid email.",
            "ERR_MSG_172" : "Invalid org_type.",
            'ERR_MSG_173' : "MITM attack blocked.",
            'ERR_MSG_174' : "roc is invalid.",
            'ERR_MSG_175' : "Sorry, we couldn't verify your identity as the provided name does not match the CIN/DIN name on record.",
            'ERR_MSG_176' : "Please provide correct Member ID (ICAI).",
            'ERR_MSG_177' : "Please provide proper Authorization Letter.",
            "ERR_MSG_178" : "The PAN Number you entered is already registered with us.",
            'ERR_MSG_179' : "Please provide proper Is Authorization Status.",
            'ERR_MSG_180' : "Unauthorized access! The specified user is not active.",
            'ERR_MSG_181' : "Invalid Authorization. We cannot find your Entity Locker Account.",
            'ERR_MSG_182' : "Please provide valid consent.",
            'ERR_MSG_183' : "Please provide valid xml.",
            'ERR_MSG_184' : "Sorry we couldn't verify your PAN at the moment. Please try again later.",
            'ERR_MSG_185' : "Invalid Authorization. We cannot find your Entity Locker Account.",
            'ERR_MSG_186' : "User is already assigned department and is active.",
            'ERR_MSG_187' : "You don't have permissions to add user to department.",
            'ERR_MSG_188' : "Provided user is not linked with current entity account.",
            'ERR_MSG_189' : "You don't have permissions to Revoke to department.",
            'ERR_MSG_190' : "You don't have permissions to add user to section.",
            'ERR_MSG_191' : "You don't have permissions to perform department operations.",
            'ERR_MSG_192' : "You don't have permissions for this department",
            'ERR_MSG_193' : "Department is invalid.",
            'ERR_MSG_194' : "Section is invalid.",
            'ERR_MSG_195' : "User is already assigned section and is active.",
            'ERR_MSG_196' : "User is not active.",
            'ERR_MSG_197' : "You don't have permissions to revoke to section.",
            'ERR_MSG_198' : "You don't have permissions to revoke department operations.",
            'ERR_MSG_199' : "Please enter department name.",
            'ERR_MSG_1991': "Please enter function name.",
            'ERR_MSG_200' : "Please enter section name.",
            'ERR_MSG_201' : "Please enter role name.",
            'ERR_MSG_202' : "This section is already active.",
            'ERR_MSG_203' : "This department is already active.",
            'ERR_MSG_204' : "This access_id is invalid.",
            'ERR_MSG_207' : "Cannot save the Organisation PAN.",
            'ERR_MSG_208' : "Please provide your CIN name.",
            'ERR_MSG_209' : "Department name exceeds 100 characters.",  
            'ERR_MSG_210' : "Description exceeds 250 characters.",           
            'ERR_MSG_211' : "Please eSign your Registration Agreement to unlock full range of features offered by Entity Locker.",
            'ERR_MSG_212' : 'GSTIN is already associated with the organization.',
            'ERR_MSG_213' : "User is already assigned department and is inactive.",
            'ERR_MSG_214' : "Admin cannot revoke from his department.",
            'ERR_MSG_215' : "User type already default.",
            'ERR_MSG_216' : "User not default.",
            'ERR_MSG_217' : "Admin cannot default.",
            'ERR_MSG_218' : "Please provide valid username.",
            'ERR_MSG_219' : "You don't have permissions to make admin",
            'ERR_MSG_220' : "This user have already admin access",
            'ERR_MSG_221' : "unable to fetch profile information",

            # oc_ci lib error messages
            'UIDAI-K-100' : 'OTP not valid.  Please enter Correct OTP as sent by UIDAI.',
            'UIDAI-K-200' : 'Data currently not available with UIDAI.',
            'UIDAI-K-540' : 'Technical error while eKYC process.',
            'UIDAI-K-541' : 'Technical error while eKYC process.',
            'UIDAI-K-542' : 'Technical error while eKYC process.',
            'UIDAI-K-544' : 'Technical error while eKYC process.',
            'UIDAI-K-545' : 'Resident has opted-out of this service. This feature is not implemented currently.',
            'UIDAI-K-546' : 'Technical error while eKYC process.',
            'UIDAI-K-547' : 'Technical error while eKYC process.',
            'UIDAI-K-550' : 'Technical error while eKYC process.',
            'UIDAI-K-551' : 'Technical error while eKYC process.',
            'UIDAI-K-552' : 'Technical error while eKYC process.',
            'UIDAI-K-569' : 'Technical error while eKYC process.',
            'UIDAI-K-570' : 'Technical error while eKYC process.',
            'UIDAI-K-600' : 'Technical error while eKYC process.',
            'UIDAI-K-601' : 'Technical error while eKYC process.',
            'UIDAI-K-602' : 'Technical error while eKYC process.',
            'UIDAI-K-603' : 'Technical error while eKYC process.',
            'UIDAI-K-604' : 'Technical error while eKYC process.',
            'UIDAI-K-605' : 'Technical error while eKYC process.',
            'UIDAI-K-955' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-K-956' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-K-999' : 'Unknown error reported by UIDAI.',
            'UIDAI-1201' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-1202' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-1203' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-1204' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-1205' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-102' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-400' : 'Please enter valid OTP.',
            'UIDAI-101' : 'Please enter valid OTP.',
            'UIDAI-D-102' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-D-103' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            'UIDAI-D-104' : 'Transaction Failed at UIDAI. Please use Resend OTP option below to try again.',
            
            
            'err_401' : 'Unauthorised Access.',
            'err_480' : 'Your DigiLocker account is temporarily blocked as you have exceeded maximum failed login attempts. Please try again after 1 hour.',
            'err_481' : 'HMAC does not match.',
            'err_482' : 'invalid hmac provided.',
            'err_483' : 'Invalid client_id or client_secret.',
            'err_484' : 'Invalid aadhaar or mobile number.',
            'err_485' : 'All parameters are missing.',
            'err_486' : 'Function name required.',
            'err_487' : 'Please enter valid OTP.',
            'err_488' : 'OTP Expired.',
            'err_489' : 'This service is currently unavailable. Please try again later.',
            'err_490' : 'Session expired.',
            'err_491' : 'OTP not verified.',
            'err_492' : 'Password not changed. Please try again later.',
            'err_493' : 'Password change success.',
            'err_494' : 'This mobile number is not registered with DigiLocker.',
            'err_495' : 'This account is not active.',
            'err_496' : 'This mobile number is not registered with DigiLocker.',
            'err_497' : 'Invalid consent.',
            'err_498' : 'Invalid function name.',
            'err_499' : 'Invalid Response.',
            'err_471' : 'Please enter correct PIN.',
            'err_472' : ' Or Pin is incorrect. Please try again.',
            'err_473' : 'Please enter correct date of birth.',
            'err_474' : 'Invalid account details. Please check and try again.',
            'err_475' : 'PIN reset attempt failed. Please try again.',
            'err_476' : 'Username reset attempt failed. Please try again.',
            'err_477' : 'Username already exists. Please use a different username.',
            'err_478' : 'Mobile update failed. Please try again.',
            'err_479' : 'Please try again after 1 hour as you have exceeded maximum allowed attempts.',

            'err_101' : 'Please enter valid OTP.',
            'err_101_a' : 'Oops,something went wrong. Please try again.',
            'err_102' : 'OTP Expired.',
            'err_104' : 'Please check your network connection and try again!',
            'err_105' : 'You are not a registered user.',
            'err_106' : 'This mobile number is associated with multiple accounts. Please log in using your username or Aadhaar number.',
            'err_106_a' : ' is associated with multiple accounts. Please log in using your username or Aadhaar number.',
            'err_108' : 'Some technical error occurred. Please try again after sometime.',
            'err_109' : 'Some technical error occurred. Please try again after sometime.[#503]',
            'err_110' : 'Aadhaar number does not have verified mobile/email.',
            'err_111' : 'Aadhaar number does not have verified mobile.',
            'err_112' : 'Aadhaar number does not have both email and mobile.',
            'err_113' : 'Aadhaar number does not have both email and mobile.',
            'err_952' : 'Please wait for sometime before requesting another OTP.',
            'err_953' : 'You have exceeded the maximum attempts allowed to send OTP. Please try again after some time.',
            'err_954' : 'You have exceeded the maximum attempts allowed to Validate OTP. Please try again after some time.',
            'err_995' : 'Your Aadhaar has been suspended by UIDAI. Please visit your nearest Aadhaar enrollment center for further information.',
            'err_996' : 'Your Aadhaar has been cancelled by UIDAI. Please visit your nearest Aadhaar enrollment center for further information.',
            'err_997' : 'Your Aadhaar has been cancelled by UIDAI. Please visit your nearest Aadhaar enrollment center for further information.',
            'err_515' : 'Please enter correct Aadhaar number.',
            'err_330' : 'Biometrics details are locked by Aadhaar number holder. Please visit your nearest Aadhaar enrollment center for further information.',
            'err_403' : 'You have exceeded maximum number of Aadhaar OTP match attempts.Please generate a fresh OTP and try to authenticate again.',
            'err_998' : 'Invalid Aadhaar number.',
            'err_931' : 'Invalid Aadhaar number.',
            'err_d101' : 'Please provide aadhaar and other details.',
            'err_s102' : 'already registered with DigiLocker. You can access your account using your credentials.',
            'err_s103' : 'This number is already registered with DigiLocker. You can access into your account using your credentials.',
            'err_s103_a' : 'This Aadhaar number is already registered with DigiLocker and associated with some other account.',
            'err_s103_m' : ' is already registered with DigiLocker and associated with some other account.',
            'err_s102_m' : 'is already registered with DigiLocker. You can sign in using your credentials.',
            'err_113' : 'Some technical error occured, Please try again.',
            'err_114' : 'Some technical error occured, Please try again. [#114]',
            'err_115' : 'Some technical error occured, Please try again. [#115]', # for txnid failed
            'err_116' : 'Some technical error occured, Please try again. [#116]', # for DB error.
            'err_117' : 'Data entered does not match with the Aadhaar details. Please enter correct details as per Aadhaar.',
            'err_118' : 'Some technical error occured, Please try again. [#118]',
            'err_119' : 'Oops,something went wrong.Please try again.',
            'err_1200' : 'Your OTP has expired. Please click Resend OTP link below to generate a new OTP and try again.',
            
        }
        return msgs.get(code, '')

class Roles:
    @staticmethod
    def rule_id(code):
        rule = json.loads(CONFIG['roles'].get(code.lower()) or '{}')
        if len(rule) > 0:
            rule.pop('rule_id') # type: ignore
        return rule
    
    @staticmethod
    def rule_name(code):
        return {
            'admin':"ORGR001",
            "manager": "ORGR003",
            "user": "ORGR002"
        }.get(code, '')
