# Copyright (c) 2011-2012 CloudOps
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hmac
import hashlib
import base64
import json

from urllib import quote
from urllib2 import urlopen, HTTPError, URLError

from webob.exc import HTTPForbidden, HTTPNotFound, HTTPUnauthorized, HTTPBadRequest
from webob import Request, Response

from swift.common.utils import cache_from_env, get_logger, split_path, get_remote_client
from swift.common.middleware.acl import clean_acl, parse_acl, referrer_allowed
from time import time
from datetime import datetime

class CloudstackAuth(object):
    """
    Swift authentication via the Cloudstack API.

    ------
    SETUP:
    ------
    File: proxy-server.conf
    Add 'cs_auth' (and 'cache') to your pipeline:

        [pipeline:main]
        pipeline = catch_errors cache cs_auth proxy-server

    Optional S3 Integration - To add support for s3 calls, change the above to:

        [pipeline:main]
        pipeline = catch_errors cache swift3 cs_auth proxy-server

        [filter:swift3]
        use = egg:swift#swift3

    Add account auto creation to the proxy-server.

        [app:proxy-server]
        account_autocreate = true


    Add a filter for 'cs_auth':

        [filter:cs_auth]
        use = egg:cs_auth#cs_auth
        cs_api_url = http://127.0.0.1:8081/client/api
        cs_admin_apikey = <admin user's apikey>
        cs_admin_secretkey = <admin user's secretkey>
        swift_storage_url = http://127.0.0.1:8080


    ------
    USAGE:
    ------

    Curl:
    -----
    Request for authentication
    curl -v -H "X-Auth-User: $cloudstack_username" -H "X-Auth-Key: $cloudstack_apikey" http://127.0.0.1:8080/v1.0
    returns: $cloudstack_auth_token and $cloudstack_swift_storage_url

    Request container list
    curl -v -X GET -H "X-Auth-Token: $cloudstack_auth_token" $cloudstack_swift_storage_url


    Swift CLI:
    ----------
    Request status
    swift -v -A http://127.0.0.1:8080/v1.0 -U $cloudstack_username -K $cloudstack_apikey stat


    S3 API:
    -------
    Requires the optional step in SETUP
    (example uses the python boto lib)

    from boto.s3.connection import S3Connection, OrdinaryCallingFormat

    conn = S3Connection(aws_access_key_id=cloudstack_apikey,
                        aws_secret_access_key=cloudstack_secretkey,
                        host='127.0.0.1',
                        port=8080,
                        is_secure=False,
                        calling_format=OrdinaryCallingFormat())
    bucket = conn.create_bucket('sample_bucket')
    

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='cs_auth')
        self.reseller_prefix = conf.get('reseller_prefix', '').strip()
        self.cs_roles = ('cs_user_role', 'cs_global_admin_role', 'cs_domain_admin_role') # ORDER IS IMPORTANT: mapping to cs accounttype.
        self.cs_api_url = conf.get('cs_api_url').strip()
        self.cs_admin_apikey = conf.get('cs_admin_apikey').strip()
        self.cs_admin_secretkey = conf.get('cs_admin_secretkey').strip()
        self.cs_api = CloudstackAPI(host=self.cs_api_url, api_key=self.cs_admin_apikey, secret_key=self.cs_admin_secretkey)
        self.cs_cache_timeout = int(conf.get('cs_cache_timeout', 86400))
        self.storage_url = conf.get('swift_storage_url').strip()
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]

    def __call__(self, env, start_response):
        self.logger.debug('Initialise cs_auth middleware')
 
        # Handle s3 connections first because s3 has a unique format/use for the 'HTTP_X_AUTH_TOKEN'.
        s3 = env.get('HTTP_AUTHORIZATION', None)
        if s3 and s3.startswith('AWS'):
            s3_apikey, s3_signature = s3.split(' ')[1].rsplit(':', 1)[:]
            if s3_apikey and s3_signature:
                user_list = self.cs_api.request(dict({'command':'listUsers'}))
                if user_list:
                    for user in user_list['user']:
                        if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == s3_apikey:
                            # At this point we have found a matching user.  Authenticate them.
                            s3_token = base64.urlsafe_b64decode(env.get('HTTP_X_AUTH_TOKEN', '')).encode("utf-8")
                            if s3_signature == base64.b64encode(hmac.new(user['secretkey'], s3_token, hashlib.sha1).digest()):
                                expires = time() + self.cs_cache_timeout
                                timeout = self.cs_cache_timeout
                                token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                                identity = dict({
                                    'username':user['username'],
                                    'account':user['account'],
                                    'token':token,
                                    'domain':dict({'id':user['domainid'], 'name':user['domain']}),
                                    'roles':[self.cs_roles[user['accounttype']], user['account']],
                                    'expires':expires
                                })
                                self.logger.debug('valid s3 identity: %s' % identity)
                                # The swift3 middleware sets env['PATH_INFO'] to '/v1/<aws_secret_key>', we need to map it to the cloudstack account.
                                if self.reseller_prefix != '':
                                    env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s_%s' % (self.reseller_prefix, user['account']))
                                else:
                                    env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s' % (user['account']))        
                                memcache_client = cache_from_env(env)
                                if memcache_client:
                                    memcache_client.set('cs_token/%s' % token,
                                                        (expires, identity),
                                                        timeout=timeout)
                            else:
                                self.logger.debug('S3 credentials are not valid.')
                                env['swift.authorize'] = self.denied_response
                                return self.app(env, start_response)
                else:
                    self.logger.debug('errors: %s' % self.cs_api.errors)
                    env['swift.authorize'] = self.denied_response
                    return self.app(env, start_response)
            else:
                self.logger.debug('Invalid format of credentials')
                env['swift.authorize'] = self.denied_response
                return self.app(env, start_response)
        
        # Handle the request for authenication otherwise use the token.
        req = Request(env)
        if not s3:
            try:
                path_segs = split_path(req.path_info, minsegs=1, maxsegs=3, rest_with_last=True)
            except ValueError:
                return HTTPNotFound(request=req)

            # Check if the request is for authentication (to get a token).
            if path_segs[0] in ('auth', 'v1.0'):
                self.logger.debug('Received an authentication request')
                auth_user = env.get('HTTP_X_AUTH_USER', None)
                auth_key = env.get('HTTP_X_AUTH_KEY', None)
                if auth_user and auth_key:
                    self.logger.debug('We have a user and key, validating...')
                    user_list = self.cs_api.request(dict({'command':'listUsers', 'username':auth_user}))
                    if user_list:
                        for user in user_list['user']:
                            if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == auth_key:
                                token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                                if env.get('HTTP_X_AUTH_TTL', None):
                                    expires = time() + int(env.get('HTTP_X_AUTH_TTL'))
                                    timeout = int(env.get('HTTP_X_AUTH_TTL'))
                                else:
                                    expires = time() + self.cs_cache_timeout
                                    timeout = self.cs_cache_timeout
                                identity = dict({
                                    'username':user['username'],
                                    'account':user['account'],
                                    'token':token,
                                    'domain':dict({'id':user['domainid'], 'name':user['domain']}),
                                    'roles':[self.cs_roles[user['accounttype']], user['account']],
                                    'expires':expires
                                })
                                self.logger.debug('created identity: %s' % identity)
                                if self.reseller_prefix != '':
                                    account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(user['account']))
                                else:
                                    account_url = '%s/v1/%s' % (self.storage_url, quote(user['account']))
                                # add to memcache so it can be referenced later
                                memcache_client = cache_from_env(env)
                                if memcache_client:
                                    memcache_client.set('cs_token/%s' % token,
                                                        (expires, identity),
                                                        timeout=timeout)
                                req.response = Response(request=req,
                                                        headers={'x-auth-token':token, 
                                                                 'x-storage-token':token,
                                                                 'x-storage-url':account_url})
                                return req.response(env, start_response)
                    
                        # if we get here the user was not valid, so fail...
                        self.logger.debug('Not a valid user and key pair')
                        env['swift.authorize'] = self.denied_response
                        return self.app(env, start_response)
                    else:
                        self.logger.debug('errors: %s' % self.cs_api.errors)
                        env['swift.authorize'] = self.denied_response
                        return self.app(env, start_response)
                else:
                    self.logger.debug('Credentials missing')
                    env['swift.authorize'] = self.denied_response
                    return self.app(env, start_response)
            else:
                token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        
        if not token:
            # this is an anonymous request.  pass it through for authorize to verify.
            self.logger.debug('Passing through anonymous request')
            env['swift.authorize'] = self.authorize
            env['swift.clean_acl'] = clean_acl
            return self.app(env, start_response)

        self.logger.debug('Got token: %s' % (token))

        identity = None
        memcache_client = cache_from_env(env)
        memcache_key = 'cs_token/%s' % (token)
        memcache_result = memcache_client.get(memcache_key)
        if memcache_result:
            expires, _identity = memcache_result
            if expires > time():
                self.logger.debug('Getting identity info from memcache')
                identity = _identity

        if not identity:
            self.logger.debug("No memcache, validate via cloudstack")
            identity = self._cloudstack_validate_token(token)
            if identity and memcache_client:
                expires = identity['expires']
                memcache_client.set(memcache_key,
                                    (expires, identity),
                                    timeout=expires - time())
                ts = str(datetime.fromtimestamp(expires))
                self.logger.debug('Setting memcache expiration to %s' % ts)
            else:  # if we didn't get identity it means there was an error.
                self.logger.debug('Could not retieve an identity for this token.');
                env['swift.authorize'] = self.denied_response
                return self.app(env, start_response)

        if not identity:
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)

        self.logger.debug("Using identity: %r" % (identity))
        env['cloudstack.identity'] = identity
        env['REMOTE_USER'] = ':'.join(identity['roles'])
        env['swift.authorize'] = self.authorize
        env['swift.clean_acl'] = clean_acl
        return self.app(env, start_response)

    def _cloudstack_validate_token(self, token_claim):
        """
        Will take a token and validate it in cloudstack.
        """

        identity = None
        user_list = self.cs_api.request(dict({'command':'listUsers'}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'secretkey' in user and hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest() == token_claim:
                    expires = time() + self.cs_cache_timeout
                    identity = dict({
                        'username':user['username'],
                        'account':user['account'],
                        'token':token_claim,
                        'domain':dict({'id':user['domainid'], 'name':user['domain']}),
                        'roles':[self.cs_roles[user['accounttype']], user['account']],
                        'expires':expires
                    })
                    self.logger.debug('validated identity: %s' % identity)
                    return identity
        else:
            self.logger.debug('errors: %s' % self.cs_api.errors)
        
        return identity

    def authorize(self, req):
        env = req.environ
        identity = env.get('cloudstack.identity', {})

        try:
            version, _account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            return HTTPNotFound(request=req)

        if not _account or not _account.startswith(self.reseller_prefix):
            self.logger.debug('denied because of reseller prefix')
            return self.denied_response(req)

        # Remove the reseller_prefix from the account.
        if self.reseller_prefix != '':
            account = _account[len(self.reseller_prefix)+1:]
        else:
            account = _account
            
        self.logger.debug('we have account: %s' % account)
        
        user_roles = identity.get('roles', [])

        # If this user is part of this account or is the global admin, give access.
        if account == identity.get('account') or self.cs_roles[1] in user_roles:
            req.environ['swift_owner'] = True
            return None

        # Allow container sync
        if (req.environ.get('swift_sync_key') and req.environ['swift_sync_key'] == req.headers.get('x-container-sync-key', None) and
           'x-timestamp' in req.headers and (req.remote_addr in self.allowed_sync_hosts or get_remote_client(req) in self.allowed_sync_hosts)):
            self.logger.debug('allowing container-sync')
            return None

        # Check if Referrer allow it
        referrers, groups = parse_acl(getattr(req, 'acl', None))
        if referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in groups:
                self.logger.debug('authorizing via ACL')
                return None
            return self.denied_response(req)

        # Check if we have the group in the user_roles and allow if we do
        for role in user_roles:
            if role in groups:
                self.logger.debug('user has role %s, allowing via ACL' % (role))
                return None

        # This user is not authorized, deny request.
        return self.denied_response(req)

    def denied_response(self, req):
        """
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)


class CloudstackAPI(object):
    """
    Login and run queries against the Cloudstack API.
    Example Usage: 
    cs_api = CloudstackAPI(api_key='api_key', secret_key='secret_key'))
    accounts = cs_api.request(dict({'command':'listAccounts'}))
    if accounts:
        # do stuff with the result
    else:
        # print cs_api.errors
    
    """
    
    def __init__(self, host=None, api_key=None, secret_key=None):        
        self.host = host
        self.api_key = api_key
        self.secret_key = secret_key
        self.errors = []
        
    def request(self, params):
        """Builds a query from params and return a json object of the result or None"""
        if self.api_key and self.secret_key:
            # add the default and dynamic params
            params['response'] = 'json'
            params['apiKey'] = self.api_key

            # build the query string
            query_params = map(lambda (k,v):k+"="+quote(str(v)), params.items())
            query_string = "&".join(query_params)
            
            # build signature
            query_params.sort()
            signature_string = "&".join(query_params).lower()
            signature = quote(base64.b64encode(hmac.new(self.secret_key, signature_string, hashlib.sha1).digest()))

            # final query string...
            url = self.host+"?"+query_string+"&signature="+signature
            
            output = None
            try:
                output = json.loads(urlopen(url).read())[params['command'].lower()+'response']
            except HTTPError, e:
                self.errors.append("HTTPError: "+str(e.code))
            except URLError, e:
                self.errors.append("URLError: "+str(e.reason))
               
            return output
        else:
            self.errors.append("missing api_key and secret_key in the constructor")
            return None



def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return CloudstackAuth(app, conf)
    return auth_filter
