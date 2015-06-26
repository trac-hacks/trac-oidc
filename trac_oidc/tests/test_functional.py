# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
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
from trac.env import open_environment
from trac.web.main import dispatch_request
from webtest import TestApp

from ..authenticator import Authenticator


@pytest.fixture
def get_identity(monkeypatch):
    get_identity = mock.Mock(name='Authenticator.get_identity')
    monkeypatch.setattr(Authenticator, 'get_identity', get_identity)
    return get_identity


_counter = count(1)


@pytest.fixture
def id_token(get_identity):
    id_token = {
        'iss': 'https://example.net',
        'sub': 'sub%d' % next(_counter),
        }
    get_identity.return_value = id_token
    return id_token


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
    trac_admin(env_path, 'initenv testenv sqlite:db/trac.db svn ""')

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


@pytest.fixture
def env(env_path):
    return open_environment(env_path, use_cache=True)


TRAC_CONFIGS = [
    {
        'logging': {
            'log_level': 'INFO',
            },
        'components': {
            'trac_oidc.*': 'enabled',
            'trac.web.auth.loginmodule': 'enabled',
            },
        },
    {
        'logging': {
            'log_level': 'INFO',
            },
        'components': {
            'trac_oidc.*': 'enabled',
            'trac.web.auth.loginmodule': 'disabled',
            },
        },
    ]


@pytest.fixture(params=TRAC_CONFIGS)
def test_app(env, request):
    settings = request.param
    for section in settings:
        for name, value in settings[section].items():
            env.config.set(section, name, value)
    env.config.save()

    environ = {
        'trac.env_path': env.path,
        'HTTP_HOST': 'localhost',
        }
    return TestApp(dispatch_request, extra_environ=environ)


def is_logged_in(resp):
    # trac < 1.0.2 uses logout link
    logout_link = resp.html.find('a', href=re.compile(r'/logout(\Z|\?)'))
    if logout_link:
        assert 'Logout' in logout_link
        return True
    # trac >= 1.0.2 uses logout form
    logout_form = resp.forms.get('logout')
    if logout_form:
        assert logout_form.action.endswith('/logout')
        return True
    return False


def check_metanav(resp):
    """Sanity checks on the metanav bar

    This makes sure that we're not getting "logged in as" and "Logout"
    metanav items from both the stock LoginModule and AuthCookieManager.

    """
    metanav = resp.html.find(id='metanav')
    if is_logged_in(resp):
        logged_ins = metanav.find_all(text=re.compile(r'logged in', re.I))
        assert len(logged_ins) == 1
        logouts = metanav.find_all(text=re.compile(r'log\s*out', re.I))
        assert len(logouts) == 1


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


def test(test_app, id_token):
    id_token.update({
        'email': 'joe@example.org',
        'name': 'Joe Bloe',
        })

    resp = test_app.get('/prefs')
    check_metanav(resp)
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
    check_metanav(resp)
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
