# -*- coding: utf-8 -*-
""" Functional tests
"""
from __future__ import absolute_import

from functools import partial
from itertools import count
import json
import logging
import os
import re
from shutil import rmtree
from StringIO import StringIO
import sys
from tempfile import mkdtemp
from urllib import urlencode
from urlparse import parse_qsl, urlsplit

import pytest
from trac.admin.console import TracAdmin

import mock
from trac.web.main import dispatch_request
from webtest import TestApp


class DummyCredentials(object):
    _counter = count()

    def __init__(self, iss='https://example.org', counter=_counter):
        self.id_token = {
            'iss': iss,
            'sub': 'sub-%d' % next(self._counter),
            }
        self.profile = {}

    def authorize(self, http):
        return self

    def request(self, url):
        resp = mock.Mock(status=200)
        content = json.dumps(self.profile)
        return resp, content


@pytest.fixture
def dummy_credentials(monkeypatch):
    from ..trac_oidc import OidcPlugin
    cred = DummyCredentials()
    monkeypatch.setattr(OidcPlugin, '_step2_exchange',
                        lambda self, req, code: cred)
    return cred


def trac_admin(env_path, *commands):
    admin = TracAdmin(env_path)
    logging.disable(logging.CRITICAL)
    save_stdout, sys.stdout = sys.stdout, StringIO()
    try:
        for command in commands:
            admin.onecmd(command)
    finally:
        sys.stdout = save_stdout
        logging.disable(logging.NOTSET)


@pytest.fixture(scope='module')
def env_path(request):
    env_path = mkdtemp(suffix='.env')
    request.addfinalizer(partial(rmtree, env_path))
    trac_admin(env_path,
               'initenv testenv sqlite:db/trac.db',
               'config set logging log_level INFO',
               'config set components trac_oidc.* enabled')

    # Create dummy client_secret.json
    web_secrets = {
        'auth_uri': "https://accounts.example.com/auth",
        'token_uri': "https://accounts.example.com/token",
        'client_id': "ID",
        'client_secret': "SEKRET",
        'redirect_uris': [],
        }
    client_secret_file = os.path.join(env_path, 'conf/client_secret.json')
    with open(client_secret_file, 'w') as fp:
        fp.write(json.dumps({'web': web_secrets}))

    return env_path


@pytest.fixture(params=[
    # Run test both with and with the stock LoginModule
    ['config set components trac.web.auth.loginmodule enabled'],
    ['config set components trac.web.auth.loginmodule disabled'],
    ])
def test_app(env_path, request):
    trac_admin(env_path, *request.param)
    environ = {
        'trac.env_path': env_path,
        'HTTP_HOST': 'localhost',
        }
    return TestApp(dispatch_request, extra_environ=environ)


def is_logged_in(resp):
    # trac < 1.0.2 uses logout link
    logout_link = resp.html.find('a', href=re.compile(r'/logout\Z'))
    if logout_link:
        assert 'Logout' in logout_link
        return True
    # trac >= 1.0.2 uses logout form
    logout_form = resp.forms.get('logout')
    if logout_form:
        assert logout_form.action.endswith('/logout')
        return True
    return False


def oauth_redirect_url(auth_url):
    """ Simulate Oauth2 authentication.
    """
    params = dict(parse_qsl(urlsplit(auth_url).query))
    assert params['access_type'] == 'online'
    assert params['response_type'] == 'code'
    assert 'email' in params['scope']
    state = params['state']
    redirect_uri = params['redirect_uri']
    redirect_uri += '?' + urlencode({'state': state, 'code': 'CODE'})
    return redirect_uri


def test(test_app, dummy_credentials):
    dummy_credentials.id_token['email'] = 'joe@example.org'
    dummy_credentials.profile['name'] = 'Joe Bloe'

    resp = test_app.get('/prefs')
    assert not is_logged_in(resp)

    # Initial login
    resp = resp.click('^Login .* Google$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    assert resp.status == '302 Found'
    auth_url = resp.location

    resp = test_app.get(oauth_redirect_url(auth_url))
    assert resp.status == '302 Found'

    resp = resp.follow()
    assert is_logged_in(resp)

    # Check that session was created
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joe Bloe'

    # Update name
    prefs['name'] = 'Joseph Blow'
    resp = prefs.submit()
    resp = resp.maybe_follow()
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joseph Blow'

    # Logout
    if 'logout' in resp.forms:
        resp = resp.forms['logout'].submit()
    else:
        # trac < 1.0.2 uses link for logout
        resp = resp.click('Logout')
    resp = resp.follow()
    assert not is_logged_in(resp)

    # Log in again
    resp = resp.click('^Login .* Google$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    assert resp.status == '302 Found'
    auth_url = resp.location
    resp = test_app.get(oauth_redirect_url(auth_url))
    resp = resp.follow()
    assert is_logged_in(resp)

    # Check that we got the same session
    resp = test_app.get('/prefs')
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joseph Blow'
