from tornado import gen
from tornado.log import gen_log
from tornado.escape import json_decode
from tornado.httpclient import AsyncHTTPClient
import base64

class Sso(object):
    def auth_token(self, token):
        """Return {'user_id': '', 'token': '', 'expire': 1470738102},
        if token is not expire, set expire to 0,
        if authentication fail, return None
        """
        raise NotImplementedError("Please Implement this method")
        
class StormpathSso(Sso):
    """Example Stormpath
    """
    BASE_URL = 'https://api.stormpath.com/v1'
    APPLICATION_ID = '63iFKOIfBxPzy5yxzZPhPJ'
    API_KEY_ID = '3LQUT48NDAVERJRG0MXW42RIN'
    API_KEY_SECRET = 'WLZ4fIWVG0XA7H2azYgS3NNWKi50PdDMpNTGY+RinkQ'
    
    @gen.coroutine
    def auth_token(self, token):
        auth_url = "%s/applications/%s/authTokens/%s" % (self.BASE_URL, self.APPLICATION_ID, token)
        basic = base64.b64encode(self.API_KEY_ID + ':' + self.API_KEY_SECRET)
        headers = {"Authorization": "Basic %s" %basic}
        http_client = AsyncHTTPClient()
        try:
            res = yield http_client.fetch(auth_url, headers=headers)
            json_res = json_decode(res.body)
            user_id = json_res['account']['href'].split('/')[-1]
            token = json_res['jwt']
            expire = json_res['expandedJwt']['claims']['exp']
        except Exception as e:
            gen_log.debug(e)
            raise gen.Return(None)
        data = {'user_id': user_id, 'token': token, 'expire': expire}
        # print data
        raise gen.Return(data)
        
sso = StormpathSso()
