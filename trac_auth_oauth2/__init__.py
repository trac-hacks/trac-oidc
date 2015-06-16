# -*- coding: utf-8 -*-
"""
FIXME:

Change name to trac_openidconnect (or something).  (We are not using
Oauth2, but rather OpenID Connect (which is built on OAauth2).)

"""
from __future__ import absolute_import

from base64 import urlsafe_b64decode
import json
from genshi.builder import tag
from sanction import Client
from trac.core import (
    implements,
    Component,
    )
from trac.web.api import parse_arg_list, IRequestHandler
from trac.web.chrome import INavigationContributor

try:                            # FIXME: cleanup
    from acct_mgr.web_ui import LoginModule
except ImportError:
    from trac.web.auth import LoginModule

CLIENT_CONFIG = json.loads('''{"web":{"auth_uri":"https://accounts.google.com/o/oauth2/auth","client_secret":"khLdYd_-ZsT0zOmXLSs7V0Pk","token_uri":"https://accounts.google.com/o/oauth2/token","client_email":"533933068542-nkc62isflaii5uitv1q678pnp4thavoo@developer.gserviceaccount.com","redirect_uris":["https://www.example.com/oauth2callback"],"client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/533933068542-nkc62isflaii5uitv1q678pnp4thavoo@developer.gserviceaccount.com","client_id":"533933068542-nkc62isflaii5uitv1q678pnp4thavoo.apps.googleusercontent.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","javascript_origins":["https://www.example.com"]}}''')


class Oauth2Plugin(Component):
    implements(
        INavigationContributor,
        IRequestHandler,
        )

    def get_oauth2_client(self, req):
        web = CLIENT_CONFIG['web']
        config = {
            'auth_endpoint': web['auth_uri'],
            'token_endpoint': web['token_uri'],
            'client_id': web['client_id'],
            'client_secret': web['client_secret'],
            }
        return Client(**config)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'trac_auth_oauth2'

    def get_navigation_items(self, req):
        if req.authname and req.authname != 'anonymous':
            username = req.session.get('name') or req.authname
            if not self.env.is_component_enabled(LoginModule):
                yield ('metanav', 'trac_auth_oauth2',
                       'logged in as %s' % username),
                yield ('metanav', 'trac_auth_oauth2',  # FIXME: correct?
                       tag.a('Logout',
                             href=req.href.trac_auth_oauth2_logout()))
        else:
            client = self.get_oauth2_client(req)
            auth_url = client.auth_uri(
                scope='openid email',
                redirect_uri=req.abs_href.oauth2(),
                # FIXME: state=csrf_token,
                **{'openid.realm': 'http://localhost:8000/'}
                )
            yield ('metanav', 'trac_auth_oauthy2',
                   tag.a(('OAuth2 Login'), href=auth_url))

    # IRequestHandler

    def match_request(self, req):
        return req.path_info == '/oauth2'

    def process_request(self, req):
        if req.path_info == '/oauth2':
            return self._do_login(req)

    def _do_login(self, req):
        get_args = dict(parse_arg_list(req.query_string))
        client = self.get_oauth2_client(req)
        client.request_token(
            redirect_uri=req.abs_href.oauth2(),  # FIXME: necessary?
            code=get_args['code'])
        openid_id = sub = None
        from pprint import pprint
        if client.id_token:
            token = unpack_token(client.id_token)
            pprint(token)
            openid_id = token.get('openid_id')
            sub = token.get('sub')
        print sub, openid_id
        import pdb; pdb.set_trace()


def unpack_token(token):
    """ Unpack JWT token.

    Does not verify signature.  Since, in our case, we get the token direct
    from google, there is no need for signature verification.

    """
    header, payload, sig = token.split('.')
    # restore padding
    payload += '=' * (-len(payload) % 4)
    data = urlsafe_b64decode(payload.encode('latin1'))
    return json.loads(data)
