# -*- coding: utf-8 -*-
"""
FIXME:

Change name to trac_openidconnect (or something).  (We are not using
Oauth2, but rather OpenID Connect (which is built on OAauth2).)

"""
from __future__ import absolute_import

from itertools import chain, count
import json
import os
from urllib import urlencode
from urlparse import parse_qsl

from genshi.builder import tag
import httplib2
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from trac.config import BoolOption, PathOption
from trac.perm import PermissionSystem
from trac.util import hex_entropy
from trac.util.translation import _
from trac.web.auth import LoginModule
from trac.web.chrome import add_warning
from trac.web.session import DetachedSession

# FIXME: integrate with AccountManagerPlugin
# try:
#     from acct_mgr.web_ui import LoginModule
# except ImportError:
#     from trac.web.auth import LoginModule

RETURN_URL_SKEY = 'trac_oidc.return_url'
CSRF_TOKEN_SKEY = 'trac_oidc.csrf_token'
SUBJECT_SKEY = 'trac_oidc.subject'
IDENTITY_URL_SKEY = 'openid_session_identity_url_data'


class OidcPlugin(LoginModule):
    """ Authenticate via OpenID Connect

    """

    # implements(IAuthenticator, INavigationContributor, IRequestHandler)

    client_secret_file = PathOption(
        'trac_oidc', 'client_secret_file', 'client_secret.json',
        """Path to client_secret file.  Relative paths are interpreted
        relative to the ``conf`` subdirectory of the trac environment.""")

    # deprecated
    absolute_trust_root = BoolOption(
        'openid', 'absolute_trust_root', 'true',
        """Whether we should use absolute trust root or by project.""")

    def __init__(self):
        self.show_logout_link = not self.env.is_component_enabled(LoginModule)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'trac_oidc.login'

    def get_navigation_items(self, req):
        oidc_href = req.href.trac_oidc
        if req.authname and req.authname != 'anonymous':
            if self.show_logout_link:
                yield ('metanav', 'trac_oidc.login',
                       _('logged in as %(name)s',
                         user=req.authname,
                         name=req.session.get('name') or req.authname))
                yield ('metanav', 'trac_oidc.logout',
                       tag.form(tag.div(
                           tag.button(_('Logout'),
                                      name='logout', type='submit')),
                                action=oidc_href('logout'), method='post',
                                id='logout', class_='trac-logout'))
        else:
            yield ('metanav', 'trac_oidc.login',
                   tag.a(_('Login using Google'), href=oidc_href('login')))

    # IRequestHandler

    def match_request(self, req):
        return req.path_info in ('/trac_oidc/login', '/trac_oidc/logout',
                                 '/trac_oidc/redirect')

    def process_request(self, req):
        if req.path_info.endswith('/login'):
            req.session[RETURN_URL_SKEY] = _get_return_url(req)
            flow = self._get_oauth2_flow(req)
            auth_url = flow.step1_get_authorize_url()
            return req.redirect(auth_url)
        elif req.path_info.endswith('/logout'):
            return_url = _get_return_url(req)
            self._do_logout(req)
            return req.redirect(return_url)
        elif req.path_info.endswith('/redirect'):
            return_url = req.session.get(RETURN_URL_SKEY, req.base_url)
            credentials = self._get_credentials(req)
            new_csrf_token(req)  # reset csrf_token
            if credentials:
                # Authentication successful
                authname = self._authname_for_credentials(credentials)
                if authname:
                    self.log.info("Logging in as %r", authname)
                    # FIXME: hackish
                    req.environ['REMOTE_USER'] = authname
                    self._do_login(req)  # LoginModule._do_login
            return req.redirect(return_url)

    def _get_oauth2_flow(self, req):
        """ Get an ``oauth2client`` “flow” instance.
        """
        conf_dir = os.path.join(self.env.path, 'conf')
        client_secret = os.path.join(conf_dir, self.client_secret_file)
        redirect_uri = req.abs_href.trac_oidc('redirect')
        openid_realm = self._get_openid_realm(req)
        self.log.debug('openid_realm = %r', openid_realm)

        flow = flow_from_clientsecrets(client_secret,
                                       scope='openid email',
                                       redirect_uri=redirect_uri)
        flow.params.update({
            'access_type': 'online',
            'state': get_csrf_token(req),
            'openid.realm': openid_realm,
            })
        return flow

    def _get_credentials(self, req):
        """ Extract ``code`` from query_string and exchange it for oauth2
        credentials.

        On success returns the ``oauth2client`` credentials instance,
        otherwise returns ``None``.

        """
        args = dict(parse_qsl(req.query_string))
        csrf_token = get_csrf_token(req)

        def failed(msg):
            self.log.info("Authentication failed: %s", msg)
            add_warning(req, "Authentication failed: %s", msg)

        if 'error' in args:
            return failed(args['error'])
        elif 'code' not in args:
            return failed("no 'code' in redirect")
        elif strings_differ(args.get('state', ''), csrf_token):
            return failed("incorrect 'state' in redirect")

        return self._step2_exchange(req, args['code'])

    def _step2_exchange(self, req, code):
        """ Exchange ``code`` for Oauth2 credentials

        This is broken out into its own method mainly so that it can be
        monkey-patched for test purposes.

        """
        flow = self._get_oauth2_flow(req)
        try:
            return flow.step2_exchange(code)
        except FlowExchangeError as ex:
            add_warning(req, "Failed to retrieve credentials: %s", ex)

    def _authname_for_credentials(self, credentials):
        """Find ``authname`` for credentials.

        Returns the *session id* of the authenticated session
        associated with the given credentials. If no existing
        authenticated session is found, a new one is created.

        """
        authname = self._find_session(credentials)
        if not authname:
            # There is no authenticated session for the user,
            # create a new one
            # XXX: should it be configurable whether this happens?
            profile = self._get_openid_profile(credentials)
            authname = self._authname_for(credentials, profile)
            settings = self._settings_for(credentials, profile)
            id_token = credentials.id_token
            subject_id = subject_uri(id_token['iss'], id_token['sub'])
            settings[SUBJECT_SKEY] = subject_id
            ds = new_session(self.env, authname, settings)
            authname = ds.sid   # may have changed in order to make unique
            self.log.info(
                "Created new authenticated session for %s"
                " with settings %r",
                authname, settings)
        return authname

    def _find_session(self, credentials):
        """ Find the authenticated session corresponding to credentials.

        Returns the session id, or ``None`` if no corresponding authenticated
        session is found.

        """
        id_token = credentials.id_token
        issuer = id_token['iss']
        subject = id_token['sub']
        subject_id = subject_uri(issuer, subject)
        authname = self._find_session_by_attr(
            SUBJECT_SKEY, subject_id, 'oidc subject')
        if authname is None:
            self.log.debug(
                "No authenticated session found for oidc subject %s",
                subject_id)
            # Fallback to using the OpenIDv2 identity URL which
            # (may have) been set by the ``TracAuthOpenId`` plugin
            if 'openid_id' in id_token:
                identity_url = id_token['openid_id']
                authname = self._find_session_by_attr(
                    IDENTITY_URL_SKEY, identity_url, 'oid identity url')
                if authname:
                    self.log.info(
                        "Adding oidc subject %s for %s with oid identity %s",
                        subject_id, authname, identity_url)
                    # Set the subject id so we can find it next time
                    # by the normal method
                    ds = DetachedSession(self.env, authname)
                    ds[SUBJECT_SKEY] = subject_id
                    ds.save()
                else:
                    self.log.debug(
                        "No authenticated session found for oid identity %s",
                        identity_url)
        return authname

    def _find_session_by_attr(self, attr_name, attr_value, attr_desc=None):
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
        sids = [row[0] for row in cursor.fetchall()]
        if len(sids) > 1:
            authnames = ', '.join("'%s'" % sid for sid in sids)
            desc = attr_desc or attr_name
            self.log.warning("Multiple users share the same %s %s: %s",
                             desc, attr_value, authnames)
        return sids[0] if sids else None

    def _get_openid_profile(self, credentials):
        """ Get profile in OpenID Connect format.
        """
        http = credentials.authorize(httplib2.Http())
        resp, content = http.request(
            "https://www.googleapis.com/plus/v1/people/me/openIdConnect")
        if resp.status == 200:
            return json.loads(content)
        else:
            self.log.warn(
                "Failed to retrieve profile (%d %s): %s",
                resp.status, resp.reason, content)
            return None

    def _authname_for(self, credentials, profile):
        """ Determine authname (sid) to use for newly created authenticated
        sessions.

        """
        id_token = credentials.id_token
        # XXX Should we check id_token[email_verified]? I think it's not
        # necessary, since we're only using the email as a session id.
        subject = id_token['sub']
        assert subject
        email = id_token.get('email')
        fullname = profile and profile.get('name')
        return email or fullname or subject

    def _settings_for(self, credentials, profile):
        """ Determine settings to use for newly created authenticated sessions.

        """
        settings = {}
        id_token = credentials.id_token
        # XXX Should we check id_token[email_verified]? Probably not,
        # since we allow the user to change his email setting anyway.
        if 'email' in id_token:
            settings['email'] = id_token['email']
        if profile:
            if 'name' in profile:
                settings['name'] = profile['name']
            # FIXME: fallback to given_name and family_name if no name?
        return settings

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


def uniquifier_suffixes():
    return chain([""], (" (%d)" % n for n in count(2)))


def new_session(env, authname_base, settings=None):
    permissions = PermissionSystem(env).get_all_permissions()
    users_and_groups_with_permissions = set(user for user, perm in permissions)

    def permission_exists_for(authname):
        return authname in users_and_groups_with_permissions

    for suffix in uniquifier_suffixes():
        authname = authname_base + suffix
        if permission_exists_for(authname):
            continue
        ds = DetachedSession(env, authname)
        # At least in 0.12.2, this means no session exists.
        is_new = ds.last_visit == 0 and len(ds) == 0
        if is_new:
            break

    if settings:
        for key, value in settings.items():
            if value is not None:
                ds[key] = value
        ds.save()

    return ds


def _get_return_url(req):
    # Save referer so that we can return there when done
    referer = req.get_header('Referer')
    base = req.base_url.rstrip('/') + '/'
    if referer and referer.startswith(base):
        # only redirect to referer if it is from the same site
        return referer
    else:
        return base


def get_csrf_token(req):
    csrf_token = req.session.get(CSRF_TOKEN_SKEY)
    if not csrf_token:
        csrf_token = hex_entropy()
        req.session[CSRF_TOKEN_SKEY] = csrf_token
    return csrf_token


def new_csrf_token(req):
    req.session.pop(CSRF_TOKEN_SKEY, None)


def strings_differ(string1, string2):
    """Check whether two strings differ while avoiding timing attacks.

    This function returns True if the given strings differ and False
    if they are equal.  It's careful not to leak information about *where*
    they differ as a result of its running time, which can be very important
    to avoid certain timing-related crypto attacks:

        http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf

    Ripped-off from pyramid.util.

    """
    if len(string1) != len(string2):
        return True

    invalid_bits = 0
    for a, b in zip(string1, string2):
        invalid_bits += a != b

    return invalid_bits != 0
