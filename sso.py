#!/usr/bin/env python
# coding=utf-8
import base64
import re
import time
import json
import jwt
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

from tornado import gen
from tornado.log import gen_log
from tornado.escape import json_decode
from tornado.httpclient import AsyncHTTPClient


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


class FirebaseSso(Sso):
    """Example Firebase Authentication, Locally verify.
    More info:
    https://firebase.google.com/docs/auth/
    https://firebase.google.com/docs/auth/server/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    """
    PROJECT_ID = 'wioapp-c70a8'
    CERT_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'

    public_cert = {}
    cert_expire = 0

    @gen.coroutine
    def auth_token(self, token):
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        if not kid:
            raise Exception("The JWT token not include KID")

        if int(time.time()) >= self.cert_expire:
            try:
                yield self.request_cert()
            except Exception as e:
                raise Exception("Requires JWT public certificate failure, {}".format(str(e)))

        try:
            cert_obj = load_pem_x509_certificate(self.public_cert.get(kid).encode('utf-8'), default_backend())
            public_key = cert_obj.public_key()
            payload = jwt.decode(token, public_key, audience=self.PROJECT_ID, algorithms=['RS256'], verify=True)
        except Exception as e:
            raise Exception("Verify JWT token failure, {}".format(str(e)))

        raise gen.Return({'user_id': payload['user_id'], 'token': token, 'expire': payload['exp'], "ext": payload})

    @gen.coroutine
    def request_cert(self):
        http_client = AsyncHTTPClient()
        try:
            res = yield http_client.fetch(self.CERT_URL)
            self.public_cert = json.loads(res.body)
            cc = res.headers['Cache-Control']
            max_age = re.search("max-age=([0-9]+)", cc).groups()[0]
            self.cert_expire = int(time.time()) + int(max_age)
        except:
            raise


sso = FirebaseSso()
