import json
import os, dotenv, configparser
dotenv.load_dotenv()

CONFIG = configparser.ConfigParser()

thisfolder = os.path.dirname(os.path.abspath(__file__))
root_folder = os.path.dirname(thisfolder)
config_ini_file = os.path.join(root_folder, os.getenv('config_path', ''))
CONFIG.read(config_ini_file)


APP_ENVIRONMENT = os.getenv('environment')
DEBUG_MODE = os.getenv('debug_mode','').lower() == 'true'
D_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

SUCCESS = "success"
ERROR = "error"
ERROR_DES = "error_description"
STATUS = "status"
COUNT= "count"
MESSAGE = "msg"
RESPONSE = "response"
RESPONSE_CODE = "response_code"
HEADER = "headers"
HEADERS = "headers"
REQUEST = "request"
ENDPOINT = "endpoint"
ERROR_DESCRIPTION= "error_description"

FORCED_ACCESS_TEMPLATE = 'pages/force_access.html'

class Constants:
    @staticmethod
    def constant(code):
        # imports from config
        return dict(map(lambda x : (x[0].upper(), x[1]), list(CONFIG.items('constants')))).get(code, '')


class Messages:
    @staticmethod
    def message(code):
        msgs = {
            'MSG_100': "User Added.",
            'MSG_101': "Transfer Successful.",
            'MSG_102': "User Deactivated.",
            'MSG_103': "User Activated.",
            'MSG_104': "Entity Profile Updated Successfully.",
            'MSG_105': "User Role Updated.",
            'MSG_106': "Entity Avatar Updated.",
            'MSG_107': "OTP has been sent to your email id.",
            'MSG_108': "OTP Verified Successfully.",
            'MSG_109': "Request Sent.",
            'MSG_110': "CIN Updated Successfully.",
            'MSG_111': "ICAI Updated Successfully.",
            'MSG_112': "Udyam Updated Successfully.",
            
        }
        return msgs.get(code, '')


class Errors:
    @staticmethod
    def error(code):
        msgs = {
            'ERR_MSG_100': "Unsupported character in %s.!",
            'ERR_MSG_101': "Invalid name.",
            'ERR_MSG_102': "Invalid original name.",
            'ERR_MSG_103': "Invalid notification ID.",
            'ERR_MSG_104': "Invalid Digilocker ID.",
            'ERR_MSG_105': "Invalid published date.",
            'ERR_MSG_106': "Invalid valid through date.",
            'ERR_MSG_107': "Jtoken is missing.",
            'ERR_MSG_108': "Unauthorized access.",
            'ERR_MSG_109': "Invalid operation.",
            'ERR_MSG_110': "No data found.",
            'ERR_MSG_111': "Some technical error occurred.",
            'ERR_MSG_112': "Invalid message ID.",
            'ERR_MSG_113': "Invalid read date.",
            'ERR_MSG_114': "No input data.",
            'ERR_MSG_115': "Invalid action taken.",
            'ERR_MSG_116': "Mobile number is required.",
            'ERR_MSG_117': "Aadhaar number is required.",
            'ERR_MSG_118': "All required data must be provided.",
            'ERR_MSG_119': "User is invalid or required.",
            'ERR_MSG_120': "Client ID is invalid or required.",
            'ERR_MSG_121': "Timestamp is invalid or required.",
            'ERR_MSG_122': "Hmac is invalid or required.",
            'ERR_MSG_123': "Org ID is invalid.",
            'ERR_MSG_124': "Org alias is invalid.",
            'ERR_MSG_125': "Please provide org ID or org alias.",
            'ERR_MSG_126': "Please provide Digilocker ID or access ID.",
            'ERR_MSG_127': "Rule ID is invalid.",
            'ERR_MSG_128': "Your OTP has expired. Please click the 'Resend OTP' link below to generate a new OTP and try again.",
            'ERR_MSG_129': "This mobile number is not registered with DigiLocker.",
            'ERR_MSG_130': "Please enter a valid OTP.",
            'ERR_MSG_131': "Please enter the correct OTP.",
            'ERR_MSG_132': "Please provide correct DIN.",
            'ERR_MSG_133': "Please provide a valid Aadhaar number.",
            'ERR_MSG_134': "Please provide a valid txn.",
            'ERR_MSG_135': "Please provide consent.",
            'ERR_MSG_136': "Please provide the correct rule name.",
            'ERR_MSG_137': "Invalid is_active.",
            'ERR_MSG_138': "Invalid Aadhaar number.",
            'ERR_MSG_139': "Invalid consent.",
            'ERR_MSG_140': "A technical error occurred. Please try again. [#115]", # for txnid failed
            'ERR_MSG_141': "Invalid access ID.",
            'ERR_MSG_142': "Invalid org type.",
            'ERR_MSG_143': "Invalid email.",
            'ERR_MSG_144': "Invalid date of incorporation.",
            'ERR_MSG_145': "Invalid DIN.",
            'ERR_MSG_146': "Invalid CIN.",
            'ERR_MSG_147': "Invalid GSTIN.",
            'ERR_MSG_148': "Unauthorised access! This resource is only accessible to directors.",
            'ERR_MSG_149': "The mobile number is invalid.",
            'ERR_MSG_150': "Unauthorised access! This resource is only accessible to administrators.",
            'ERR_MSG_151': "Password must be exactly 10 characters long and consist only of uppercase and lowercase letters and/or digits.",
            'ERR_MSG_152': "Unauthorized access! You do not have access to this Entity.",
            'ERR_MSG_153': "Unauthorized access! The specified user is not active.",
            'ERR_MSG_154': "You are only allowed to have %s active users."%CONFIG['roles']['max_users'],
            'ERR_MSG_155': "Service is temporarly not available. Please try again after some time.",
            'ERR_MSG_156': "This user account is already registered with the entity.",
            'ERR_MSG_157': "User is not registered with this Entity.",
            'ERR_MSG_158': "Too many attempts.",
            'ERR_MSG_159': "OTP entered is incorrect. You are left with %s attempts.",
            'ERR_MSG_160': "MITM attack blocked.",
            'ERR_MSG_161': "Last active director can not be deactivated. Either transfer your ownership or add a new director.",
            'ERR_MSG_162': "Designation is not recognized.",
            'ERR_MSG_163': "roc is invalid.",
            'ERR_MSG_164': "Din number is not registered with the entity.",
            'ERR_MSG_165': "Provided CIN number seems to be incorrect. We could not match Entity name with MCA, please verify and try again.",
            'ERR_MSG_166': "Your session has expired! Please start again.",
            'ERR_MSG_167': "Lockerid is invalid.",
            'ERR_MSG_168': "Server Ip is empty.",
            'ERR_MSG_169': "Public Ip is empty.",
            'ERR_MSG_170': "Browser name is empty.",
            'ERR_MSG_171': "Latitude is empty.",
            'ERR_MSG_172': "Longitude is empty.",
            'ERR_MSG_173': "Please provide a valid transaction id.",
            'ERR_MSG_174': "Multiple requests found.",
            'ERR_MSG_175': "Your link has expired! Please request for a new link.",
            'ERR_MSG_176': "Invalid Authorization. We cannot find your Entity Locker Account.",
            'ERR_MSG_177': "Request is already cancelled or expired.",
            'ERR_MSG_178': "Request is %s.",
            'ERR_MSG_179': "This user request is already processed.",
            'ERR_MSG_180': "You have exhausted your maximum attempts for registration! Please request for a new link.",
            'ERR_MSG_181': "You have exhausted your maximum attempts for updating email.",
            "ERR_MSG_182": "The CIN you entered is already registered with us.",
            "ERR_MSG_183": "XML data not found.",
            'ERR_MSG_184': "Invalid ICAI.",
            'ERR_MSG_185': 'We could not validate you CIN. Please enter correct CIN.',
            "ERR_MSG_186" : "The ICAI you entered is already registered with us.",
            'ERR_MSG_187': "An active request with provided mobile number exists.",
            'ERR_MSG_188': "An user with provided email is already registered with the entity.",
            'ERR_MSG_189': "An active request with provided email exists.",
            'ERR_MSG_190': "An active request with provided aadhaar exists.",
            'ERR_MSG_191': "An user with provided mobile number is already registered with the entity.",
            'ERR_MSG_192': "Consent not Found.",
            'ERR_MSG_193': "Doc_name is empty.",
            'ERR_MSG_194': "Please eSign your Registration Agreement to unlock full range of features offered by Entity Locker.",
            'ERR_MSG_195': "Please provide valid Udyam Number.",
            "ERR_MSG_196": "The Udyam Number you entered is already registered with us.",
            'ERR_MSG_197': "Provided Udyam number seems to be incorrect. We could not match Entity name with MSME, please verify and try again.",
            'ERR_MSG_198': "Name of the director does not match with DIN. Please verify and try again.",
            'ERR_MSG_199': "Please provide your CIN name.",
            'ERR_MSG_200': "Entity already has a registered CIN Number.",
            'ERR_MSG_201': "Entity already has a registered Udyam Number.",
            'ERR_MSG_202': 'We could not validate you DIN. Please enter correct DIN.',
            'ERR_MSG_203': 'Your DIN is not registered with the Entity.',
            'ERR_MSG_204': 'Provided date is invalid. Please provide date in fromat DDMMYYYY',
            'ERR_MSG_205' : "An user can only be associated with %s Entities."%CONFIG['roles']['max_organizations'],
            'ERR_MSG_206': "Invalid Jtoken.",
            'ERR_MSG_207': "Cannot save the Organisation PAN.",
            'ERR_MSG_208': "The GSTIN you entered is already registered with us.",
            'ERR_MSG_209': "An user with provided Aadhaar number is already registered with the entity.",
            'ERR_MSG_210': "Access ID not found.",
            'ERR_MSG_211': "Digilockerid not found.",
            'ERR_MSG_212': "User already revoked.",
            'ERR_MSG_213': "User already Active.",
            "ERR_MSG_214": "The PAN Number you entered is already registered with us.",
            "ERR_MSG_215" : "Key is None .",
            "ERR_MSG_216" : "The GSTIN Number you entered is already registered with us.",
            "ERR_MSG_223" : "The %s you entered is currently %s for approval.",
            
            

            'UIDAI-K-100' : 'OTP is not valid. Please enter Correct OTP as sent by UIDAI.',
            'UIDAI-K-200' : 'Data is currently not available with UIDAI.',
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
            'err_112' : 'CIN details required.',
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
            'err_1201' : 'An unexpected issue occurred. Please try again later.',
            
            
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
            "admin": "ORGR001",
            "user": "ORGR002",
            "manager": "ORGR003"
        }.get(code, '')
    