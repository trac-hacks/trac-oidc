# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from functools import partial
import json

import httplib2
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from trac.core import TracError
from trac.util import hex_entropy

from .util import strings_differ, DeferredMapping


class AuthenticationFailed(TracError):
    """ Authentication failed.

    Access was denied by the OpenID Provider.

    """


class AuthenticationError(TracError):
    """ Authentication error.

    An error occurred during authentication.

    """


class Authenticator(object):
    STATE_SKEY = 'trac_oidc.oauth_state'

    def __init__(self, client_secret_file, redirect_uri,
                 openid_realm=None, log=None):
        self.flow = flow_from_clientsecrets(client_secret_file,
                                            scope='openid email',
                                            redirect_uri=redirect_uri)
        self.flow.params['access_type'] = 'online'
        if openid_realm:
            # openid_realm is a (probably) google-only extension which
            # causes openid_id, the old OpenID2 identity url for the user,
            # to be returned in the id_token.
            self.flow.params['openid.realm'] = openid_realm
        self.log = log

    def get_auth_url(self, req):
        flow = self.flow
        state = hex_entropy()
        req.session[self.STATE_SKEY] = state
        flow.params['state'] = state
        return flow.step1_get_authorize_url()

    def get_identity(self, req):
        """ Get identity after redirect from the provider.

        This exchanges the returned *code* for credentials, including
        the *id_token*.

        The *id_token* is returned as a mapping (read-only dict-like)
        object.  It contains (among possible others) the following keys:

          - ``iss``, ``sub``: The oidc issuer and subject identifiers
          - ``preferred_username`` (optional)
          - ``name`` (optional)
          - ``email`` (optional)
          - ``openid_id`` (optional)

        """
        code = self._get_code(req)
        credentials = self._get_credentials(code)
        # Avoid fetching profile until/unless required
        deferred_profile = partial(self._get_openid_profile, credentials)
        id_token = DeferredMapping(credentials.id_token, deferred_profile)
        return id_token

    def _get_code(self, req):
        """ Extract ``code`` from redirect
        """
        args = req.args
        error = args.getfirst('error')
        state = args.getfirst('state', '')
        code = args.getfirst('code')
        expected_state = req.session.pop(self.STATE_SKEY, None)

        if error is not None:
            raise AuthenticationFailed(error)
        elif not expected_state or strings_differ(state, expected_state):
            raise AuthenticationError("incorrect 'state' in redirect")
        elif not code:
            raise AuthenticationError("no 'code' returned in redirect")
        return code

    def _get_credentials(self, code):
        """ Exchange code for credentials
        """
        try:
            return self.flow.step2_exchange(code)
        except FlowExchangeError as ex:
            raise AuthenticationError(
                "Failed to retrieve credentials: %s" % ex)

    def _get_openid_profile(self, credentials):
        """ Get profile in OpenID Connect format.
        """
        http = credentials.authorize(httplib2.Http())
        resp, content = http.request(
            "https://www.googleapis.com/plus/v1/people/me/openIdConnect")
        if resp.status != 200:
            if self.log:
                self.log.warn(
                    "Failed to retrieve profile (%d %s): %s",
                    resp.status, resp.reason, content)
            return {}
        try:
            return json.loads(content)
        except ValueError:
            if self.log:
                self.log.error("Response is not valid JSON: %s", content)
            return {}
