# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
"""
from __future__ import absolute_import

from io import BytesIO
from itertools import islice
from urllib import urlencode

import mock                     # FIXME: use trac.test.Mock?
import pytest
from trac.core import implements, Component
from trac.perm import PermissionSystem
from trac.test import EnvironmentStub
from trac.web.api import Request
from trac.web.session import DetachedSession

from ..api import ILoginManager
from ..authenticator import AuthenticationError, AuthenticationFailed


@pytest.fixture
def disable_loginmodule():
    return False


@pytest.fixture
def env(disable_loginmodule):
    if disable_loginmodule:
        return EnvironmentStub(enable=['trac_oidc.*'])
    else:
        return EnvironmentStub()


def dummy_request(env, cookies_from=None, query=None):
    environ = {
        'trac.base_url': env.base_url,
        'wsgi.url_scheme': 'http',
        'wsgi.input': BytesIO(),
        'SCRIPT_NAME': '/trac.cgi',
        'REQUEST_METHOD': 'GET',
        'SERVER_NAME': 'example.org',
        'SERVER_PORT': '80',
        'HTTP_HOST': 'example.org',
        }
    if query:
        environ['QUERY_STRING'] = urlencode(query)
    if cookies_from:
        outcookie = cookies_from.outcookie
        cookie = '; '.join('%s=%s' % (name, morsel.value)
                           for name, morsel in outcookie.items())
        environ['HTTP_COOKIE'] = cookie
    start_response = mock.Mock(name='start_response')
    req = Request(environ, start_response)
    req.session = {}
    req.chrome = {'warnings': [], 'notices': []}
    req.redirect = mock.Mock(name='req.redirect', spec=())
    req.authname = 'anonymous'
    return req


@pytest.fixture
def req(env):
    return dummy_request(env)


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
    def authenticator(self, plugin, monkeypatch):
        monkeypatch.setattr(plugin, '_get_authenticator', mock.Mock())
        return plugin._get_authenticator.return_value

    @pytest.fixture
    def id_token(self, authenticator):
        id_token = {
            'iss': 'https://example.net',
            'sub': '42',
            }
        authenticator.get_identity.return_value = id_token
        return id_token

    @pytest.fixture
    def userdb(self, plugin):
        plugin.userdb = mock.Mock(name='plugin.userdb')
        return plugin.userdb

    @pytest.fixture
    def login_manager(self, env):
        env.enabled[DummyLoginManager] = True
        return DummyLoginManager(env)

    def assert_redirected(self, req, location=mock.ANY):
        assert req.redirect.mock_calls == [mock.call(location)]

    def test_get_active_navigation_item(self, plugin, req):
        active_item = plugin.get_active_navigation_item(req)
        assert active_item == 'trac_oidc.login'

    @pytest.mark.parametrize('authname', [None, 'anonymous'])
    def test_get_navigation_items_logged_out(self, plugin, req, authname):
        req.environ.update({
            'PATH_INFO': '/foo',
            'QUERY_STRING': 'q=bar',
            })
        req.authname = authname
        items = list(plugin.get_navigation_items(req))
        assert len(items) == 1
        category, name, text = items[0]
        assert category == 'metanav'
        assert name == 'trac_oidc.login'
        assert 'Login using Google' in str(text)
        assert '/trac_oidc/login' in str(text)
        assert '/trac_oidc/login?return_to=%2Ffoo%3Fq%3Dbar' in str(text)

    def test_get_navigation_items_logged_in(self, env, plugin, req):
        plugin.show_logout_link = True
        req.environ.update({
            'PATH_INFO': '/foo',
            'QUERY_STRING': 'q=bar',
            })
        req.authname = 'user1'
        items = {}
        for category, name, text in plugin.get_navigation_items(req):
            assert category == 'metanav'
            items[name] = text
        assert len(items) == 2
        assert 'logged in as user1' in items['trac_oidc.login']
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

    @pytest.mark.parametrize('disable_loginmodule', [True])
    def test_match_request_login_module_disabled(self, plugin, req):
        req.environ['PATH_INFO'] = '/login'
        assert plugin.match_request(req)

    def test_process_request_logout(self, plugin, req, login_manager):
        login_manager.authname = 'someuser'
        req.environ['PATH_INFO'] = 'trac_oidc/logout'
        plugin.process_request(req)
        assert login_manager.authname is None
        self.assert_redirected(req)

    def test_process_request_login(self, plugin, req, authenticator):
        auth_url = authenticator.get_auth_url.return_value
        req.environ['PATH_INFO'] = 'trac_oidc/login'
        plugin.process_request(req)
        assert 'trac_oidc.return_url' in req.session
        self.assert_redirected(req, auth_url)

    def test_process_request_redirect(self, plugin, req,
                                      login_manager, id_token):
        id_token['preferred_username'] = 'user23'
        req.environ['PATH_INFO'] = 'trac_oidc/redirect'
        plugin.process_request(req)
        assert login_manager.authname == 'user23'
        assert "username 'user23' has been created" in req.chrome['notices'][0]
        self.assert_redirected(req, req.base_url)

    def test_retrieve_id(self, plugin, req, id_token):
        assert plugin._retrieve_id(req) == id_token

    @pytest.mark.parametrize('error_class', [
        AuthenticationError,
        AuthenticationFailed,
        ])
    def test_retrieve_id_failure(self, plugin, req,
                                 authenticator, error_class):
        authenticator.get_identity.side_effect = error_class('test message')
        assert plugin._retrieve_id(req) is None
        assert 'test message' in req.chrome['warnings'][0]

    def test_find_or_create_session_finds_existing(self, plugin, req, userdb):
        id_token = {}
        authname = userdb.find_session.return_value
        assert plugin._find_or_create_session(req, id_token) == authname

    def test_find_or_create_session_creates_new(self, plugin, req, userdb):
        id_token = {}
        userdb.find_session.return_value = None
        authname = userdb.create_session.return_value
        assert plugin._find_or_create_session(req, id_token) == authname

    def test_remember_user(self, plugin, req, login_manager):
        plugin._remember_user(req, 'someuser')
        assert login_manager.authname == 'someuser'

    def test_forget_user(self, plugin, req, login_manager):
        login_manager.authname = 'someuser'
        plugin._forget_user(req)
        assert login_manager.authname is None

    def test_get_authenticator(self, plugin, req, monkeypatch):
        from .. import trac_oidc
        Authenticator = mock.Mock()
        monkeypatch.setattr(trac_oidc, 'Authenticator', Authenticator)
        plugin.config.set('trac_oidc', 'client_secret_file', '/secrets.json')
        redirect_url = 'http://example.org/trac.cgi/trac_oidc/redirect'
        openid_realm = 'http://example.org/'
        authenticator = plugin._get_authenticator(req)
        assert authenticator is Authenticator.return_value
        assert Authenticator.mock_calls == [
            mock.call('/secrets.json', redirect_url, openid_realm, plugin.log),
            ]

    def test_get_openid_realm(self, plugin, req):
        assert plugin._get_openid_realm(req) == 'http://example.org/'

    def test_get_openid_realm_no_absolute_trust_root(self, env, plugin, req):
        env.config.set('openid', 'absolute_trust_root', 'false')
        assert plugin._get_openid_realm(req) == 'http://example.org/trac.cgi'

    @pytest.mark.parametrize('return_to', [
        '/foo?bar=baz',
        '/foo/bar',
        '?bar=baz',
        '',
        ])
    def test_get_return_url(self, env, plugin, return_to):
        base = 'http://example.org/trac.cgi'
        req = dummy_request(env, query={'return_to': return_to})
        assert plugin._get_return_url(req) == (base + return_to)

    @pytest.mark.parametrize('return_to', [
        '/..',
        '..',
        '../',
        'http://example.net/foo',
        'http:/foo',
        'http:foo',
        '//example.net/foo',
        ])
    def test_get_return_url_bad_return_to(self, env, plugin, return_to):
        base = 'http://example.org/trac.cgi'
        req = dummy_request(env, query={'return_to': return_to})
        assert plugin._get_return_url(req) == base


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

    def test_get_active_navigation_item(self, manager, req):
        assert manager.get_active_navigation_item(req) is None

    def test_get_navigation_items(self, manager, req):
        assert list(manager.get_navigation_items(req)) == []

    def test_match_request(self, manager, req, path_info='/logout'):
        req.environ['PATH_INFO'] = path_info
        assert not manager.match_request(req)


def test_temporary_environ():
    from ..trac_oidc import _temporary_environ
    req = mock.Mock(environ={'foo': 'bar'})
    with _temporary_environ(req, foo='other', baz='set'):
        assert req.environ['foo'] == 'other'
        assert req.environ['baz'] == 'set'
    assert req.environ['foo'] == 'bar'
    assert 'baz' not in req.environ


class TestUserDatabase(object):
    @pytest.fixture
    def userdb(self, env):
        from ..trac_oidc import UserDatabase
        return UserDatabase(env)

    @pytest.fixture
    def helper(self, userdb):
        userdb.helper = mock.Mock(name='UserDatabase.helper')
        return userdb.helper

    def test_find_session(self, env, userdb):
        ds = DetachedSession(env, 'foo')
        ds['trac_oidc.subject'] = 'https://example.net?sub=42'
        ds.save()
        sid = userdb.find_session({'iss': 'https://example.net', 'sub': '42'})
        assert sid == 'foo'

    def test_find_session_by_identity_url(self, env, userdb):
        bare_id_token = {'iss': 'https://example.net', 'sub': '42'}
        id_token = {'iss': 'https://example.net', 'sub': '42',
                    'openid_id': 'https://example.org/foo'}
        ds = DetachedSession(env, 'bar')
        ds['openid_session_identity_url_data'] = 'https://example.org/foo'
        ds.save()
        assert userdb.find_session(bare_id_token) is None
        assert userdb.find_session(id_token) == 'bar'
        assert userdb.find_session(bare_id_token) == 'bar'

    def test_find_session_returns_none(self, userdb):
        id_token = {'iss': 'https://example.net', 'sub': '42'}
        assert userdb.find_session(id_token) is None

    def test_create_session(self, userdb, helper):
        id_token = {
            'iss': 'https://example.net',
            'sub': '42',
            'preferred_username': 'username',
            'name': 'Joe',
            'email': 'user@example.net',
            }
        authname = userdb.create_session(id_token)
        assert helper.mock_calls == [
            mock.call.create_session('username', {
                'trac_oidc.subject': 'https://example.net?sub=42',
                'name': 'Joe',
                'email': 'user@example.net',
                }),
            ]
        assert authname == helper.create_session.return_value

    def test_find_session_by_oidc_subject(self, userdb, helper, caplog):
        helper.find_session_by_attr.return_value = ['user1', 'user2']
        assert userdb.find_session_by_oidc_subject('iss', 'sub') == 'user1'
        assert "Multiple users share the same oidc iss" in caplog.text()

    def test_find_session_by_openid_id(self, userdb, helper, caplog):
        helper.find_session_by_attr.return_value = ['user1', 'user2']
        assert userdb.find_session_by_openid_id('id') == 'user1'
        assert "Multiple users share the same openid url" in caplog.text()

    def test_associate_session(self, env, userdb):
        userdb.associate_session('foo', 'https://example.net', '42')
        ds = DetachedSession(env, 'foo')
        assert ds[userdb.SUBJECT_SKEY] == 'https://example.net?sub=42'

    def test_preferred_username(self, userdb):
        id_token = {
            'preferred_username': 'joeblow',
            'email': 'joe@example.net',
            'name': 'Joe',
            'sub': '42',
            }
        assert userdb.preferred_username(id_token) == 'joeblow'

    def test_preferred_username_from_email(self, userdb):
        id_token = {
            'email': 'joe@example.net',
            'name': 'Joe',
            'sub': '42',
            }
        assert userdb.preferred_username(id_token) == 'joe@example.net'

    def test_preferred_username_from_name(self, userdb):
        id_token = {
            'name': 'Joe',
            'sub': '42',
            }
        assert userdb.preferred_username(id_token) == 'Joe'

    def test_preferred_username_from_sub(self, userdb):
        id_token = {
            'sub': '42',
            }
        assert userdb.preferred_username(id_token) == '42'

    def test_default_attributes(self, userdb):
        id_token = {
            'name': 'Joe',
            'email': 'joe@example.net',
            }
        assert userdb.default_attributes(id_token) == {
            'name': 'Joe',
            'email': 'joe@example.net',
            }

    def test_default_attributes_defaults(self, userdb):
        id_token = {}
        assert userdb.default_attributes(id_token) == {
            'name': '',
            'email': '',
            }

    @pytest.mark.parametrize('iss, sub, subject_id', [
        ('example.com', 'foo', 'https://example.com?sub=foo'),
        ('https://example.com/x', 'foo&bar',
         'https://example.com/x?sub=foo%26bar'),
        ])
    def test_subject_uri(self, userdb, iss, sub, subject_id):
        assert userdb.subject_uri(iss, sub) == subject_id


class TestSessionHelper(object):
    @pytest.fixture
    def helper(self, env):
        from ..trac_oidc import SessionHelper
        return SessionHelper(env)

    def test_find_session_by_attr(self, env, helper):
        ds = DetachedSession(env, 'foo')
        ds['bar'] = 'baz'
        ds.save()
        ds = DetachedSession(env, 'wrong')
        ds['bar'] = 'not baz'
        ds.save()
        assert helper.find_session_by_attr('bar', 'baz') == ['foo']

    def test_find_session_by_attr_returns_none(self, env, helper):
        assert helper.find_session_by_attr('bar', 'baz') == []

    def test_find_session_by_attr_returns_most_recent(self, env, helper,
                                                      monkeypatch):
        def make_session(sid, last_visit):
            monkeypatch.setattr("time.time", lambda: last_visit)
            ds = DetachedSession(env, sid)
            ds['bar'] = 'baz'
            ds.save()
        make_session('old', 1000)
        make_session('new', 3000)
        make_session('inbetween', 2000)
        assert helper.find_session_by_attr('bar', 'baz') == [
            'new',
            'inbetween',
            'old',
            ]

    def test_create_session(self, env, helper):
        sid = helper.create_session('foo', {'name': 'Joe'})
        assert sid == 'foo'
        ds = DetachedSession(env, 'foo')
        assert ds['name'] == 'Joe'

    def test_create_session_skips_existing(self, helper):
        sid1 = helper.create_session('foo', {'name': 'Joe'})
        assert sid1 == 'foo'
        sid2 = helper.create_session('foo', {'name': 'Joe'})
        assert sid2 == 'foo (2)'

    def test_create_session_skips_sid_with_permission(self, env, helper):
        PermissionSystem(env).grant_permission('foo', 'TRAC_ADMIN')
        sid = helper.create_session('foo', {'name': 'Joe'})
        assert sid == 'foo (2)'

    def test_create_session_raises_value_error(self, helper):
        with pytest.raises(ValueError):
            helper.create_session('foo', {})

    def test_uniquifier_suffixes(self, helper):
        suffixes = helper.uniquifier_suffixes()
        assert list(islice(suffixes, 3)) == ['', ' (2)', ' (3)']

    def test_permission_exists(self, env, helper):
        assert not helper.permission_exists_for('foo')
        PermissionSystem(env).grant_permission('foo', 'TRAC_ADMIN')
        assert helper.permission_exists_for('foo')
