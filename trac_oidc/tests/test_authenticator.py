# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
"""
from __future__ import absolute_import

import json
import logging
from urlparse import parse_qsl, urlsplit, urlunsplit

import mock
from oauth2client.client import FlowExchangeError
import pytest


@pytest.fixture
def redirect_url():
    return 'http://localhost/trac_oidc/redirect'


@pytest.fixture
def openid_realm():
    return 'http://example.net/'


@pytest.fixture
def web_secrets(redirect_url):
    return {
        'auth_uri': "https://accounts.example.com/auth",
        'token_uri': "https://accounts.example.com/token",
        'client_id': "ID",
        'client_secret': "SEKRET",
        'redirect_uris': [redirect_url],
        }


@pytest.fixture
def client_secret_file(tmpdir, web_secrets):
    secret_file = tmpdir.join('client_secret.json')
    secret_file.write(json.dumps({'web': web_secrets}))
    return str(secret_file)


class _RequestArgs(dict):
    getfirst = dict.get


class DummyRequest(object):
    def __init__(self, query=None, oauth_state=None):
        self.args = _RequestArgs(query or {})
        self.session = {}
        if oauth_state is not None:
            self.oauth_state = oauth_state

    @property
    def oauth_state(self):      # pragma: NO COVER
        return self.session['trac_oidc.oauth_state']

    @oauth_state.setter
    def oauth_state(self, state):  # pragma: NO COVER
        self.session['trac_oidc.oauth_state'] = state

    @oauth_state.deleter
    def oauth_state(self):      # pragma: NO COVER
        del self.session['trac_oidc.oauth_state']


class TestAuthenticator(object):
    @pytest.fixture
    def log(self):
        return logging.getLogger('Trac')

    @pytest.fixture
    def authenticator(self, client_secret_file, redirect_url, openid_realm,
                      log):
        from ..authenticator import Authenticator
        return Authenticator(client_secret_file, redirect_url,
                             openid_realm, log)

    def test_flow(self, authenticator,
                  redirect_url, openid_realm, web_secrets):
        flow = authenticator.flow
        assert flow.client_secret == web_secrets['client_secret']
        assert flow.redirect_uri == redirect_url
        assert flow.params['access_type'] == 'online'
        assert flow.params['openid.realm'] == openid_realm

    def test_get_auth_url(self, authenticator, web_secrets):
        req = DummyRequest()
        auth_url = authenticator.get_auth_url(req)
        split = urlsplit(auth_url)
        assert urlunsplit((split.scheme, split.netloc, split.path, '', '')) \
            == web_secrets['auth_uri']
        query = dict(parse_qsl(split.query))
        state = query['state']
        assert state
        assert req.session[authenticator.STATE_SKEY] == state

    def test_get_identity(self, authenticator):
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'},
                           oauth_state='STATE')
        authenticator._get_credentials = mock.Mock()
        authenticator._get_openid_profile = mock.Mock(return_value={})
        credentials = authenticator._get_credentials.return_value
        credentials.id_token = {'iss': 'https://example.net', 'sub': '42'}
        id_token = authenticator.get_identity(req)
        assert dict(id_token) == credentials.id_token

    def test_get_identity_resets_state(self, authenticator):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'},
                           oauth_state='STATE')
        authenticator._get_credentials = mock.Mock()
        authenticator._get_openid_profile = mock.Mock(return_value={})
        credentials = authenticator._get_credentials.return_value
        credentials.id_token = {'iss': 'https://example.net', 'sub': '42'}
        authenticator.get_identity(req)
        with pytest.raises(AuthenticationError):
            authenticator.get_identity(req)

    def test_get_code(self, authenticator):
        state = 'abcdef'
        req = DummyRequest(query={'code': 'CODE', 'state': state},
                           oauth_state=state)
        assert authenticator._get_code(req) == 'CODE'

    def test_get_code_authentication_failure(self, authenticator):
        from ..authenticator import AuthenticationFailed
        req = DummyRequest(query={'error': 'error message'})
        with pytest.raises(AuthenticationFailed) as exc_info:
            authenticator._get_code(req)
        assert 'error message' in exc_info.exconly()

    @pytest.mark.parametrize('state, oauth_state', [
        ('wrong', 'somestate'),
        (None, 'somestate'),
        (None, None),
        ('unexpected', None),
        ])
    def test_get_code_incorrect_state(self, authenticator,
                                      state, oauth_state):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'state': state} if state else None,
                           oauth_state=oauth_state)
        with pytest.raises(AuthenticationError):
            authenticator._get_code(req)

    def test_get_code_missing_code(self, authenticator):
        from ..authenticator import AuthenticationError
        state = 'abcdef'
        req = DummyRequest(query={'state': state}, oauth_state=state)
        with pytest.raises(AuthenticationError):
            authenticator._get_code(req)

    def test_get_credentials(self, authenticator):
        authenticator.flow = flow = mock.Mock(name='flow')
        credentials = authenticator._get_credentials('CODE')
        assert flow.mock_calls == [mock.call.step2_exchange('CODE')]
        assert credentials == flow.step2_exchange.return_value

    def test_get_credentials_failure(self, authenticator):
        from ..authenticator import AuthenticationError
        authenticator.flow = flow = mock.Mock(name='flow')
        flow.step2_exchange.side_effect = FlowExchangeError('testing')
        with pytest.raises(AuthenticationError):
            authenticator._get_credentials('CODE')

    def test_get_openid_profile(self, authenticator):
        credentials = mock.Mock(name='credentials')
        http = credentials.authorize.return_value
        resp = mock.Mock(name='Response', status=200)
        content = b'{"foo": "bar"}'
        http.request.return_value = resp, content
        profile = authenticator._get_openid_profile(credentials)
        assert profile == {'foo': 'bar'}

    def test_get_openid_profile_failure(self, authenticator, caplog):
        credentials = mock.Mock(name='credentials')
        http = credentials.authorize.return_value
        resp = mock.Mock(name='Response', status=500)
        content = b'{"foo": "bar"}'
        http.request.return_value = resp, content
        assert authenticator._get_openid_profile(credentials) == {}
        assert 'Failed to retrieve profile' in caplog.text()

    def test_get_openid_profile_bad_json(self, authenticator, caplog):
        credentials = mock.Mock(name='credentials')
        http = credentials.authorize.return_value
        resp = mock.Mock(name='Response', status=200)
        content = b'}'
        http.request.return_value = resp, content
        assert authenticator._get_openid_profile(credentials) == {}
        assert 'Response is not valid JSON' in caplog.text()
