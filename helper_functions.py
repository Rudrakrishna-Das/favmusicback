import jwt
import os
from dotenv import load_dotenv

load_dotenv()

class Helper:
    def feedback(self,success,code,message='',data=None):
        for_frontend = {
            'ok':success,
            'status_code':code,
            'message':message,
            'data':data
        }
        return for_frontend
    
    def verify_user(self,token):
        result = jwt.decode(token,os.getenv('SECRET'), algorithms=os.getenv('ALOGORITHMS'))
        return result
        