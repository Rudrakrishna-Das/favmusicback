class Helper:
    def feedback(self,success,code,message='',data=None):
        for_frontend = {
            'ok':success,
            'status_code':code,
            'message':message,
            'data':data
        }
        return for_frontend