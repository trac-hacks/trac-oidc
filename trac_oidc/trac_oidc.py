# -*- coding: utf-8 -*-
""" A plugin to support trac authentication using google's *OpenID
Connect* provider.

"""
from __future__ import absolute_import

from contextlib import contextmanager
from itertools import chain, count
import os
from urllib import urlencode
from urlparse import urlsplit

from genshi.builder import tag
from trac.config import BoolOption, PathOption
from trac.core import implements, Component, ExtensionPoint
from trac.perm import PermissionSystem
from trac.util.translation import _
from trac.web.api import IAuthenticator, IRequestHandler
from trac.web.auth import LoginModule
from trac.web.chrome import add_notice, add_warning, INavigationContributor
from trac.web.session import DetachedSession

from .api import ILoginManager
from .authenticator import (
    Authenticator,
    AuthenticationError,
    AuthenticationFailed,
    )
from .compat import is_component_enabled, logout_link


class OidcPlugin(Component):
    """ Authenticate via OpenID Connect

    """
    implements(INavigationContributor, IRequestHandler)

    RETURN_URL_SKEY = 'trac_oidc.return_url'

    client_secret_file = PathOption(
        'trac_oidc', 'client_secret_file', 'client_secret.json',
        """Path to client_secret file.  Relative paths are interpreted
        relative to the ``conf`` subdirectory of the trac environment.""")

    # deprecated
    absolute_trust_root = BoolOption(
        'openid', 'absolute_trust_root', 'true',
        """Whether we should use absolute trust root or by project.""")

    login_managers = ExtensionPoint(ILoginManager)

    def __init__(self):
        # We should show our own "Logout" link only if the stock
        # LoginModule is disabled.
        self.show_logout_link = not is_component_enabled(self.env, LoginModule)

        self.userdb = UserDatabase(self.env)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'trac_oidc.login'

    def get_navigation_items(self, req):
        oidc_href = req.href.trac_oidc
        path_qs = req.path_info
        if req.query_string:
            path_qs += '?' + req.query_string

        if not req.authname or req.authname == 'anonymous':
            # Not logged in, show login link
            login_link = tag.a(_('Login using Google'),
                               href=oidc_href('login', return_to=path_qs))
            yield 'metanav', 'trac_oidc.login', login_link

        elif self.show_logout_link:
            # Logged in and LoginModule is disabled, show logout link
            yield ('metanav', 'trac_oidc.login',
                   _('logged in as %(user)s', user=req.authname))
            yield ('metanav', 'trac_oidc.logout',
                   logout_link(oidc_href, return_to=path_qs))

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info in ('/trac_oidc/login', '/trac_oidc/logout',
                                 '/trac_oidc/redirect')

    def process_request(self, req):
        if req.path_info.endswith('/logout'):
            return_url = self._get_return_url(req)
            self._forget_user(req)
            return req.redirect(return_url)
        elif req.path_info.endswith('/login'):
            # Start the login process by redirectory to OP
            req.session[self.RETURN_URL_SKEY] = self._get_return_url(req)
            authenticator = self._get_authenticator(req)
            return req.redirect(authenticator.get_auth_url(req))
        elif req.path_info.endswith('/redirect'):
            # Finish the login process after redirect from OP
            return_url = req.session.pop(self.RETURN_URL_SKEY, req.abs_href())
            id_token = self._retrieve_id(req)
            if id_token:
                authname = self._find_or_create_session(req, id_token)
                assert authname
                self.log.debug("Logging in as %r", authname)
                self._remember_user(req, authname)
            return req.redirect(return_url)

    # private methods

    def _retrieve_id(self, req):
        """ Retrieve oidc id_token from provider.

        Returns ``None`` if authentication was unsuccessful for any reason.

        """
        authenticator = self._get_authenticator(req)
        try:
            return authenticator.get_identity(req)
        except AuthenticationFailed as ex:
            self.log.info("Authentication failed: %s", ex)
            add_warning(req, "Authentication failed: %s", ex)
        except AuthenticationError as ex:
            self.log.error("Authentication error: %s", ex)
            add_warning(req, "Authentication error: %s", ex)

    def _find_or_create_session(self, req, id_token):
        """ Find or create authenticated session for subject.
        """
        userdb = self.userdb
        authname = userdb.find_session(id_token)
        if not authname:
            # There is no authenticated session for the user,
            # create a new one
            # XXX: should it be configurable whether this happens?
            authname = userdb.create_session(id_token)
            add_notice(req, _(
                "Hello! You appear to be new here. "
                "A new authenticated session with "
                "username '%(authname)s' has been created for you.",
                authname=authname))
        return authname

    def _remember_user(self, req, authname):
        for lm in self.login_managers:
            lm.remember_user(req, authname)

    def _forget_user(self, req):
        for lm in self.login_managers:
            lm.forget_user(req)

    def _get_authenticator(self, req):
        conf_dir = os.path.join(self.env.path, 'conf')
        client_secret_file = os.path.join(conf_dir, self.client_secret_file)
        redirect_url = req.abs_href.trac_oidc('redirect')
        openid_realm = self._get_openid_realm(req)
        self.log.debug('openid_realm = %r', openid_realm)
        return Authenticator(client_secret_file, redirect_url,
                             openid_realm, self.log)

    def _get_openid_realm(self, req):
        """ Get the OpenID realm.

        This computes the OpenID realm in exactly the same manner
        that the ``TracAuthOpenID`` plugin does.

        Note that I'm not sure this is really the “right” way to do it,
        but, since we want to get back the same identity URLs from google
        as we did using ``TracAuthOpenID``, here we are.

        """
        href = req.href()
        abs_href = self.env.abs_href()
        if href and abs_href.endswith(href):
            base_url = abs_href[:-len(href)]
        else:                   # pragma: NO COVER
            base_url = abs_href

        if self.absolute_trust_root:
            path = '/'
        else:
            path = href
        return base_url + path

    @staticmethod
    def _get_return_url(req):
        return_to = req.args.getfirst('return_to', '/')
        # We expect return_to to be a URL relative to the trac's base_path.
        # Be paranoid about this.
        scheme, netloc, path, query, anchor = urlsplit(return_to)
        if scheme or netloc or '..' in path.split('/') or anchor:
            # return url looks suspicious, ignore it.
            return req.abs_href()
        return_url = req.abs_href(path)
        if query:
            return_url += '?' + query
        return return_url


class AuthCookieManager(LoginModule):
    """Manage the authentication cookie.

    This handles setting the trac authentication cookie and updating
    the ``auth_cookie`` table in the trac db.

    XXX: We use the stock ``trac.web.auth.LoginModule`` to do this,
    however, as you can see, this takes a bit of hacking...

    """
    implements(IAuthenticator, ILoginManager)

    # ILoginManager methods

    def remember_user(self, req, authname):
        with _temporary_environ(req, REMOTE_USER=authname):
            self._do_login(req)  # LoginModule._do_login

    def forget_user(self, req):
        # HACK: In trac >= 1.0.2, LoginModule._do_logout does nothing
        # unless request.method == POST.
        with _temporary_environ(req, REQUEST_METHOD='POST'):
            self._do_logout(req)

    # More hackage: override INavigationContributor and
    # IRequestHandler methods inherited from LoginModule.

    def get_active_navigation_item(self, req):
        pass

    def get_navigation_items(self, req):
        return ()

    def match_request(self, req):
        return False

    def process_request(self, req):
        pass                    # pragma: NO COVER


@contextmanager
def _temporary_environ(req, **kwargs):
    """ A context manager used to teporarily modify ``req.environ``.
    """
    environ = req.environ
    req.environ = environ.copy()
    req.environ.update(kwargs)
    try:
        yield req.environ
    finally:
        req.environ = environ


class UserDatabase(Component):
    """Code to map OpenID identities to trac authnames.

    """
    abstract = True

    SUBJECT_SKEY = 'trac_oidc.subject'
    IDENTITY_URL_SKEY = 'openid_session_identity_url_data'

    def __init__(self):
        self.helper = SessionHelper(self.env)

    def find_session(self, id_token):
        """ Find existing authenticated session corresponding to identity.

        Returns the session id, or ``None`` if no corresponding authenticated
        session is found.

        """
        iss, sub = id_token['iss'], id_token['sub']
        identity_url = id_token.get('openid_id')

        authname = self.find_session_by_oidc_subject(iss, sub)
        if not authname and identity_url:
            # Fallback to using the OpenIDv2 identity URL which
            # (may have) been set by the ``TracAuthOpenId`` plugin
            authname = self.find_session_by_openid_id(identity_url)
            if authname:
                self.log.info(
                    "Claiming session %s with oid identity %s for (%s, %s)",
                    authname, identity_url, iss, sub)
                self.associate_session(authname, iss, sub)
        return authname

    def create_session(self, id_token):
        """ Create a brand new authenticated session for identity

        """
        subject_id = self.subject_uri(id_token['iss'], id_token['sub'])
        preferred_username = self.preferred_username(id_token)
        attributes = {self.SUBJECT_SKEY: subject_id}
        attributes.update(self.default_attributes(id_token))
        authname = self.helper.create_session(preferred_username, attributes)
        self.log.info(
            "Created new authenticated session for %s with attributes %r",
            authname, attributes)
        return authname

    def find_session_by_oidc_subject(self, iss, sub):
        subject_id = self.subject_uri(iss, sub)
        sids = self.helper.find_session_by_attr(self.SUBJECT_SKEY, subject_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same oidc iss=%r, sub=%r: %s",
                iss, sub, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def find_session_by_openid_id(self, openid_id):
        sids = self.helper.find_session_by_attr(self.IDENTITY_URL_SKEY,
                                                openid_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same openid url %s: %s",
                openid_id, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def associate_session(self, authname, iss, sub):
        ds = DetachedSession(self.env, authname)
        ds[self.SUBJECT_SKEY] = self.subject_uri(iss, sub)
        ds.save()

    @staticmethod
    def preferred_username(id_token):
        """Get the preferred username for the user.
        """
        sub = id_token['sub']
        assert sub
        return (
            id_token.get('preferred_username')
            or id_token.get('email')
            or id_token.get('name')
            or sub)

    @staticmethod
    def default_attributes(id_token):
        """Get extra attributes to be set on newly created sessions.
        """
        return {
            'name': id_token.get('name', ''),
            'email': id_token.get('email', ''),
            }

    @staticmethod
    def subject_uri(iss, sub):
        """Return a subject identifier.

        The subject identifier is a single string which combines the
        issuer (``iss``) and subject (``sub``) from the OpenID Connect
        id_token.

        Note that, AFAIK, this method of combining ``iss`` and ``sub``
        into a single string is not in any specification — I just made it
        up.

        """
        if '://' not in iss:
            # Normalize google's iss. See
            # http://openid.net/specs/openid-connect-core-1_0.html#GoogleIss
            iss = 'https://%s' % iss
        query_string = urlencode({'sub': sub})
        return '%s?%s' % (iss, query_string)


class SessionHelper(Component):
    """Helper for searching/manipulating the user database.

    Note that in trac, the user account/profile database is
    implemented as part of the session state storage.  User accounts
    are refered to as "authenticated sessions".  The “username” is
    referred to as the *session id* or ``sesssion.sid``.  It is also
    called the *authname* (e.g. ``req.authname``.)

    """
    abstract = True

    def __init__(self):
        self.permissions = PermissionSystem(self.env)

    def find_session_by_attr(self, attr_name, attr_value):
        """ Find an authenticated session which contain a specific attribute.

        """
        db = self.env.get_db_cnx()
        cursor = db.cursor()
        cursor.execute(
            "SELECT session.sid"
            " FROM session"
            " INNER JOIN session_attribute AS attr"
            "                  USING(sid, authenticated)"
            " WHERE session.authenticated=%s"
            "       AND attr.name=%s AND attr.value=%s"
            " ORDER BY session.last_visit DESC",
            (1, attr_name, attr_value))
        return [row[0] for row in cursor.fetchall()]

    def create_session(self, authname_base, attributes):
        """Create a new authenticated session.

        (In trac, authenticated sessions are, essentially “user accounts”,
        so this creates a new account or “login” on the trac.)

        If possible, the session is created with an ``sid`` of
        ``authname_base``.  If a session already exists with that
        ``sid``, then a suffix is added to make the ``sid`` unique.

        The attributes of the new session are initialized from the
        ``attributes`` argument, if any.

        The ``sid`` of the new session is returned.

        """
        if not attributes:
            raise ValueError("Attributes required for new session")

        for suffix in self.uniquifier_suffixes():
            authname = authname_base + suffix
            if self.permission_exists_for(authname):
                continue
            ds = DetachedSession(self.env, authname)
            # At least in 0.12.2, this means no session exists.
            is_new = ds.last_visit == 0 and len(ds) == 0
            if is_new:
                break
        for key, value in attributes.items():
            ds[key] = value or ''
        ds.save()
        return authname

    def uniquifier_suffixes(self):
        """ Suffixes used to generate unique authnames.
        """
        return chain([""], (" (%d)" % n for n in count(2)))

    def permission_exists_for(self, authname):
        return any(authname == user
                   for user, perm in self.permissions.get_all_permissions())
