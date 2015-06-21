# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from itertools import islice
import json
from urllib import urlencode

import mock                     # FIXME: use trac.test.Mock?
from oauth2client.client import FlowExchangeError
import pytest
from trac.core import implements, Component
from trac.perm import PermissionSystem
from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.session import DetachedSession

from ..api import ILoginManager


@pytest.fixture
def env():
    return EnvironmentStub()


def dummy_request(env, cookies_from=None):
    environ = {
        'trac.base_url': env.base_url,
        'wsgi.url_scheme': 'http',
        'SCRIPT_NAME': '/trac.cgi',
        'REQUEST_METHOD': 'GET',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        }
    if cookies_from:
        outcookie = cookies_from.outcookie
        cookie = '; '.join('%s=%s' % (name, morsel.value)
                           for name, morsel in outcookie.items())
        environ['HTTP_COOKIE'] = cookie
    start_response = mock.Mock(name='start_response')
    req = Request(environ, start_response)
    req.session = {}
    req.chrome = {'warnings': []}
    req.redirect = mock.Mock(name='req.redirect', spec=())
    req.authname = 'anonymous'
    return req


class TestAuthCookieManager(object):
    @pytest.fixture
    def manager(self, env):
        from ..trac_oidc import AuthCookieManager
        return AuthCookieManager(env)

    def test(self, env, manager):
        req = dummy_request(env)
        manager.remember_user(req, 'foobaroo')
        auth_req = dummy_request(env, cookies_from=req)
        assert manager.authenticate(auth_req) == 'foobaroo'

        req = dummy_request(env)
        req.authname = 'foobaroo'
        manager.forget_user(req)
        manager.forget_user(req)
        assert manager.authenticate(auth_req) is None


class DummyLoginManager(Component):
    implements(ILoginManager)

    def __init__(self):
        # Auto-enable self when instantiated
        self.compmgr.enabled[self.__class__] = True
        self.authname = None

    def remember_user(self, req, authname):
        self.authname = authname

    def forget_user(self, req):
        self.authname = None


class TestOidcPlugin(object):
    @pytest.fixture
    def plugin(self, env):
        from ..trac_oidc import OidcPlugin
        return OidcPlugin(env)

    @pytest.fixture
    def login_manager(self, env):
        env.enabled[DummyLoginManager] = True
        return DummyLoginManager(env)

    @pytest.fixture
    def req(self, env):
        return dummy_request(env)

    def assert_redirected(self, req, location=mock.ANY):
        assert req.redirect.mock_calls == [mock.call(location)]

    @pytest.fixture
    def csrf_token(self, req):
        from ..trac_oidc import get_csrf_token
        return get_csrf_token(req)

    def test_get_active_navigation_item(self, plugin, req):
        active_item = plugin.get_active_navigation_item(req)
        assert active_item == 'trac_oidc.login'

    @pytest.mark.parametrize('authname', [None, 'anonymous'])
    def test_get_navigation_items_logged_out(self, plugin, req, authname):
        req.authname = authname
        items = list(plugin.get_navigation_items(req))
        assert len(items) == 1
        category, name, text = items[0]
        assert category == 'metanav'
        assert name == 'trac_oidc.login'
        assert 'Login using Google' in str(text)
        assert '/trac_oidc/login' in str(text)

    def test_get_navigation_items_logged_in(self, env, plugin, req):
        plugin.show_logout_link = True
        req.authname = 'user1'
        req.session['name'] = 'Joe'
        items = {}
        for category, name, text in plugin.get_navigation_items(req):
            assert category == 'metanav'
            items[name] = text
        assert len(items) == 2
        assert 'logged in as Joe' in items['trac_oidc.login']
        assert 'Logout' in str(items['trac_oidc.logout'])
        assert '/trac_oidc/logout' in str(items['trac_oidc.logout'])

    @pytest.mark.parametrize('path_info', [
        '/trac_oidc/login',
        '/trac_oidc/logout',
        '/trac_oidc/redirect'
        ])
    def test_match_request(self, plugin, req, path_info):
        req.environ['PATH_INFO'] = path_info
        assert plugin.match_request(req)

    @pytest.mark.parametrize('path_info', [
        '/login',
        '/foo/logout',
        ])
    def test_match_request_does_not_match(self, plugin, req, path_info):
        req.environ['PATH_INFO'] = path_info
        assert not plugin.match_request(req)

    def test_process_request_login(self, plugin, req):
        plugin._get_oauth2_flow = mock.Mock()
        flow = plugin._get_oauth2_flow.return_value
        auth_url = flow.step1_get_authorize_url.return_value
        req.environ['PATH_INFO'] = 'trac_oidc/login'
        plugin.process_request(req)
        assert 'trac_oidc.return_url' in req.session
        self.assert_redirected(req, auth_url)

    def test_process_request_logout(self, plugin, req, login_manager):
        login_manager.authname = 'someuser'
        req.environ['PATH_INFO'] = 'trac_oidc/logout'
        plugin.process_request(req)
        assert login_manager.authname is None
        self.assert_redirected(req)

    def test_process_request_redirect(self, plugin, req, login_manager):
        from ..trac_oidc import get_csrf_token
        req.environ['PATH_INFO'] = 'trac_oidc/redirect'
        orig_csrf_token = get_csrf_token(req)
        plugin._get_credentials = mock.Mock()
        plugin._authname_for_credentials = mock.Mock(return_value='user23')

        plugin.process_request(req)

        assert login_manager.authname == 'user23'
        self.assert_redirected(req, req.base_url)
        assert get_csrf_token(req) != orig_csrf_token

    def test_process_request_redirect_auth_failed(self, plugin, req):
        from ..trac_oidc import get_csrf_token
        req.environ['PATH_INFO'] = 'trac_oidc/redirect'
        orig_csrf_token = get_csrf_token(req)
        plugin._get_credentials = mock.Mock(return_value=None)
        plugin._do_login = mock.Mock()

        plugin.process_request(req)

        assert 'REMOTE_USER' not in req.environ
        assert not plugin._do_login.called
        self.assert_redirected(req, req.base_url)
        assert get_csrf_token(req) != orig_csrf_token

    def test_get_oauth2_flow(self, env, plugin, req, tmpdir):
        redirect_url = req.base_url + '/trac_oidc/redirect'
        web_secrets = {
            'auth_uri': "https://accounts.example.com/auth",
            'token_uri': "https://accounts.example.com/token",
            'client_id': "ID",
            'client_secret': "SEKRET",
            'redirect_uris': [redirect_url],
            }
        secret_file = tmpdir.join('client_secret.json')
        secret_file.write(json.dumps({'web': web_secrets}))
        env.config.set('trac_oidc', 'client_secret_file', str(secret_file))

        flow = plugin._get_oauth2_flow(req)

        assert flow.client_secret == web_secrets['client_secret']
        assert flow.redirect_uri == redirect_url
        assert flow.params['access_type'] == 'online'

    def test_get_credentials(self, plugin, req, csrf_token):
        req.environ['QUERY_STRING'] = urlencode({
            'code': 'CODE',
            'state': csrf_token,
            })
        get_oauth2_flow = mock.Mock(name='plugin._get_oauth2_flow')
        flow = get_oauth2_flow.return_value
        plugin._get_oauth2_flow = get_oauth2_flow
        credentials = plugin._get_credentials(req)
        assert get_oauth2_flow.mock_calls == [
            mock.call(req),
            mock.call().step2_exchange('CODE'),
            ]
        assert credentials is flow.step2_exchange.return_value

    def test_get_credentials_step2_failure(self, plugin, req, csrf_token):
        req.environ['QUERY_STRING'] = urlencode({
            'code': 'CODE',
            'state': csrf_token,
            })
        get_oauth2_flow = mock.Mock(name='plugin._get_oauth2_flow')
        flow = get_oauth2_flow.return_value
        flow.step2_exchange.side_effect = FlowExchangeError('testing')
        plugin._get_oauth2_flow = get_oauth2_flow
        credentials = plugin._get_credentials(req)
        assert credentials is None
        warnings = req.chrome['warnings']
        assert "Failed to retrieve credentials: testing" in warnings

    def test_get_credentials_reports_error(self, plugin, req):
        req.environ['QUERY_STRING'] = urlencode({
            'error': 'ERROR',
            })
        credentials = plugin._get_credentials(req)
        assert credentials is None
        warnings = req.chrome['warnings']
        assert "Authentication failed: ERROR" in warnings

    def test_get_credentials_no_code(self, plugin, req):
        req.environ['QUERY_STRING'] = ''
        credentials = plugin._get_credentials(req)
        assert credentials is None
        warnings = req.chrome['warnings']
        assert "Authentication failed: no 'code' in redirect" in warnings

    def test_get_credentials_bad_state(self, plugin, req):
        req.environ['QUERY_STRING'] = urlencode({
            'code': 'CODE',
            'state': 'bad csrf_token',
            })
        credentials = plugin._get_credentials(req)
        assert credentials is None
        warnings = req.chrome['warnings']
        assert "Authentication failed: incorrect 'state' in redirect" \
            in warnings

    def test_authname_for_credentials(self, plugin):
        plugin._find_session = mock.Mock(return_value='user1')
        authname = plugin._authname_for_credentials(mock.sentinel)
        assert authname == 'user1'

    def test_authname_for_credentials_creates_session(self, env, plugin):
        id_token = {
            'iss': 'example.net',
            'sub': '123',
            'email': 'user@example.net',
            }
        profile = {
            'name': 'Joe',
            }
        credentials = mock.Mock(id_token=id_token)
        plugin._find_session = mock.Mock(return_value=None)
        plugin._get_openid_profile = mock.Mock(return_value=profile)

        authname = plugin._authname_for_credentials(credentials)
        assert authname == 'user@example.net'
        ds = DetachedSession(env, authname)
        assert ds['name'] == 'Joe'
        assert ds['email'] == 'user@example.net'

    def test_find_session(self, env, plugin):
        credentials = mock.Mock(id_token={
            'iss': 'example.net',
            'sub': '123',
            })
        ds = DetachedSession(env, 'foo')
        ds['trac_oidc.subject'] = 'https://example.net?sub=123'
        ds.save()
        sid = plugin._find_session(credentials)
        assert sid == 'foo'

    def test_find_session_by_identity_url(self, env, plugin):
        credentials = mock.Mock(id_token={
            'iss': 'example.net',
            'sub': '123',
            'openid_id': 'https://example.org/identity42',
            })
        ds = DetachedSession(env, 'foo')
        ds['openid_session_identity_url_data'] = (
            'https://example.org/identity42'
            )
        ds.save()
        sid = plugin._find_session(credentials)
        assert sid == 'foo'
        ds = DetachedSession(env, 'foo')
        assert ds['trac_oidc.subject'] == 'https://example.net?sub=123'

    def test_find_session_by_identity_returns_none(self, env, plugin):
        credentials = mock.Mock(id_token={
            'iss': 'example.net',
            'sub': '123',
            'openid_id': 'https://example.org/identity42',
            })
        sid = plugin._find_session(credentials)
        assert sid is None

    def test_find_session_by_attr(self, env, plugin):
        ds = DetachedSession(env, 'foo')
        ds['bar'] = 'baz'
        ds.save()
        sid = plugin._find_session_by_attr('bar', 'baz')
        assert sid == 'foo'

    def test_find_session_by_attr_not_found(self, env, plugin,
                                            monkeypatch, caplog):
        monkeypatch.setattr("time.time", lambda: 1000)
        ds = DetachedSession(env, 'old')
        ds['bar'] = 'baz'
        ds.save()
        monkeypatch.setattr("time.time", lambda: 1100)
        ds = DetachedSession(env, 'new')
        ds['bar'] = 'baz'
        ds.save()
        sid = plugin._find_session_by_attr('bar', 'baz', 'bar-desc')
        assert sid == 'new'
        assert 'Multiple users share the same bar-desc baz:' in caplog.text()

    def test_find_session_by_attr_returns_most_recent(self, env, plugin):
        sid = plugin._find_session_by_attr('bar', 'baz')
        assert sid is None

    def test_get_openid_profile(self, plugin):
        credentials = mock.Mock(name='credentials')
        http = credentials.authorize.return_value
        resp = mock.Mock(name='Response', status=200)
        content = b'{"foo": "bar"}'
        http.request.return_value = resp, content
        profile = plugin._get_openid_profile(credentials)
        assert profile == {'foo': 'bar'}

    def test_get_openid_profile_failure(self, plugin):
        credentials = mock.Mock(name='credentials')
        http = credentials.authorize.return_value
        resp = mock.Mock(name='Response', status=500)
        content = b'{"foo": "bar"}'
        http.request.return_value = resp, content
        profile = plugin._get_openid_profile(credentials)
        assert profile is None

    def test_authname_for_from_email(self, plugin):
        credentials = mock.Mock(id_token={
            'email': 'joe@example.com',
            'sub': '123',
            })
        profile = None
        authname = plugin._authname_for(credentials, profile)
        assert authname == 'joe@example.com'

    def test_authname_for_from_name(self, plugin):
        credentials = mock.Mock(id_token={'sub': '123'})
        profile = {'name': 'Joe'}
        authname = plugin._authname_for(credentials, profile)
        assert authname == 'Joe'

    def test_authname_for_from_sub(self, plugin):
        credentials = mock.Mock(id_token={'sub': '123'})
        profile = {'given_name': 'Joe'}
        authname = plugin._authname_for(credentials, profile)
        assert authname == '123'

    def test_settings_for_gets_email_from_id_token(self, plugin):
        credentials = mock.Mock(id_token={'email': 'joe@example.com'})
        profile = None
        settings = plugin._settings_for(credentials, profile)
        assert settings == {'email': 'joe@example.com'}

    def test_settings_for_gets_name_from_profile(self, plugin):
        credentials = mock.Mock(id_token={})
        profile = {'name': 'Joe'}
        settings = plugin._settings_for(credentials, profile)
        assert settings == {'name': 'Joe'}

    def test_get_openid_realm(self, plugin, req):
        assert plugin._get_openid_realm(req) == 'http://example.org/'

    def test_get_openid_realm_no_absolute_trust_root(self, env, plugin, req):
        env.config.set('openid', 'absolute_trust_root', 'false')
        assert plugin._get_openid_realm(req) == 'http://example.org/trac.cgi'


@pytest.mark.parametrize('iss, sub, subject_id', [
    ('example.com', 'foo', 'https://example.com?sub=foo'),
    ('https://example.com/x', 'foo&bar',
     'https://example.com/x?sub=foo%26bar'),
    ])
def test_subject_uri(iss, sub, subject_id):
    from ..trac_oidc import subject_uri
    assert subject_uri(iss, sub) == subject_id


class test_uniquifier_suffixes():
    from ..trac_oidc import uniquifier_suffixes
    assert list(islice(uniquifier_suffixes(), 3)) == ['', ' (2)', ' (3)']


class Test_new_session(object):

    def call_it(self, *args, **kwargs):
        from ..trac_oidc import new_session
        return new_session(*args, **kwargs)

    def test_creates_session(self, env):
        ds = self.call_it(env, 'foo')
        assert ds.sid == 'foo'

    def test_skips_existing_session(self, env):
        ds1 = self.call_it(env, 'foo', {'x': 'x'})
        assert ds1.sid == 'foo'
        ds2 = self.call_it(env, 'foo')
        assert ds2.sid == 'foo (2)'

    def test_skips_sid_with_permission(self, env):
        PermissionSystem(env).grant_permission('foo', 'TRAC_ADMIN')
        ds = self.call_it(env, 'foo')
        assert ds.sid == 'foo (2)'

    def test_sets_settings(self, env):
        settings = {'name': 'Foo Baroo'}
        ds = self.call_it(env, 'foo', settings)
        assert ds['name'] == 'Foo Baroo'
        ds2 = DetachedSession(env, ds.sid)
        assert ds2['name'] == 'Foo Baroo'


@pytest.mark.parametrize('base_url, referer, return_url', [
    ('http://example.com/foo', 'http://example.com/foo/bar',
     'http://example.com/foo/bar'),
    ('http://example.com/foo', 'http://example.net/foo/bar',
     'http://example.com/foo/'),
    ('http://example.com/foo', 'http://example.com/foo',
     'http://example.com/foo/'),
    ('http://example.com/foo', None,
     'http://example.com/foo/'),
    ])
def test_get_return_url(base_url, referer, return_url):
    from ..trac_oidc import _get_return_url
    req = mock.Mock(base_url=base_url,
                    get_header=mock.Mock(spec=(), return_value=referer))
    assert _get_return_url(req) == return_url


def test_get_csrf_token():
    from ..trac_oidc import get_csrf_token
    req = mock.Mock(session={})
    token = get_csrf_token(req)
    assert len(token) == 32
    assert get_csrf_token(req) == token


def test_new_csrf_token():
    from ..trac_oidc import get_csrf_token, new_csrf_token
    req = mock.Mock(session={})
    token = get_csrf_token(req)
    new_csrf_token(req)
    assert get_csrf_token(req) != token


class Test_strings_differ(object):
    def call_it(self, string1, string2):
        from ..trac_oidc import strings_differ
        return strings_differ(string1, string2)

    def test_strings_equal(self):
        assert not self.call_it('foobar', u'foobar')

    def test_strings_differ(self):
        assert self.call_it('foobar', 'foobaz')

    def test_strings_different_length(self):
        assert self.call_it('foobar', 'fooba')
