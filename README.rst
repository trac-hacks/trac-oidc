=========
Trac-oidc
=========

|version| |trac versions| |build status|

***********
Description
***********

A plugin to support authentication to trac_ using `OpenID Connect`_.

This plugin is being written in a fire-drill mode since google has
discontinued support for OpenID authentication and our trac is
currently using TracAuthOpenId_ for authentication via google.

Currently this probably only works with google as the authentication
provider.

Development takes place at http://github.com/dairiki/trac-oidc/.

This plugin is tested with trac versions 0.11, 0.12 and 1.0.

.. _OpenId Connect: http://openid.net/connect/
.. _trac: http://trac.edgewall.org/
.. _TracAuthOpenId: https://pypi.python.org/pypi/TracAuthOpenId

*****
Usage
*****

Obtain OAuth 2.0 Credentials
============================

You must obtain *OAuth 2.0 credentials* from google before you can
use this plugin.

1. Go to the `Google Developers Console`_.

.. _google developers console: https://console.developers.google.com/

2. Select a project, or create a new one.

3. In the sidebar on the left, expand **APIs & auth**.
   Next, click **APIs**.
   Select the **Enabled APIs** link in the API section to see a list
   of all your enabled APIs.

4. *Optional, but recommended*:
   Make sure that the **Google+ API** is on the list of enabled APIs.
   If you have not enabled it, select the API from the list of APIs,
   then select the Enable API button for the API.  (The Google+ API is
   used to retrieve the user’s real name on initial sign in.)

5. In the sidebar on the left, select **Credentials**.

6. If you haven't done so already, create your project's
   OAuth 2.0 credentials by clicking **Create new Client ID**,
   and providing the information needed to create the credentials.

7. The *redirect URI* used by this plugin is the base url for your trac
   followed by ``/trac_oidc/redirect``. I.e. if the top of your trac
   is at ``http://example.org/mytrac``, then the *redirect URI* will
   be ``http://example.org/mytrac/trac_oidc/redirect``.  If your trac
   is available under multiple hostnames, or under both ``http:``
   and ``https:`` schemes, then you may need to configure multiple
   *redirect URI*\s.

8. When all looks copacetic, click the **Download JSON** button (on
   the **Credentials** page) to download a JSON file containing the
   required client secrets.  Save this file to somewhere where trac
   can read it.  By default, the plugin looks for this file under the
   name ``client_secret.json`` in the ``conf`` subdirectory of the
   trac environment, however this can be configured.  (Since the file
   contains sensitive information, consider setting the file
   permissions so that not just anybody can read it.)


Install the Plugin
==================

The plugin is available from PyPI_, so it may be installed,
e.g., using *pip*::

      pip install trac-oidc

.. _pypi: https://pypi.python.org/pypi/trac-oidc

Configuration
=============

In your ``trac.ini``::

  [components]

  # You must enable the trac_oidc plugin
  trac_oidc.* = enabled

  # Optional: You probably want to disable the stock login module
  trac.web.auth.loginmodule = disabled

  [trac_oidc]

  # Optional: Specify the path to the client secrets JSON file.
  # The default is ``client_secret.json``.  Relative paths are
  # interpreted relative to the ``conf`` subdirectory of the trac
  # environment (i.e. alongside ``trac.ini``.)
  client_secret_file = /path/to/client_secret.json

  [openid]

  # Optional: This only matters if you would like to migrate
  # users created by the TracAuthOpenId_ plugin to this one.
  # In that case, the OpenID realm must be set to the same value
  # that was used by TracAuthOpenId (where it is called the *trust root*)
  # for the identity URLs to be comparable.
  #
  # If this is set, then the OpenID realm will include just the hostname,
  # otherwise the realm will include the full base path of the trac.
  # E.g. if you trac is is ``http://example.org:8080/mytrac``, then the realm
  # will be ``http://example.org:8080/`` if ``absolute_trust_root`` is set
  # and ``http://example.org:8080/mytrac`` if ``absolute_trust_root`` is
  # not set.
  #
  # The default is ``true``.
  #
  absolute_trust_root = false

*****************************
Migration from TracAuthOpenID
*****************************

If you used **only** google as the authentication provider with
TracAuthOpenId_, then you should be able to disable
``TracAuthOpenId``, configure and enable ``trac-oidc``, and things
*should* just work — users should keep their sessions (i.e. they will
retain their settings and permissions.)

.. note::

   Make sure not to change the setting of ``absolute_trust_root`` from
   whatever you were using with ``TracAuthOpenId``.

If you were using multiple authentication providers with ``TracAuthOpenId``,
it should be possible to run both ``TracAuthOpenId`` (with google disabled),
and ``trac-oidc`` together.  I have not tried this, however, and some tuning
will probably be required.

*****
To Do
*****

Possible improvements.

Generalize to work with more providers
======================================

This could be generalized to work with other OpenID Connect providers,
as well as other OAuth2-based (but non OpenID Connect) providers
(e.g. Facebook, Twitter).

Maybe using oic_ (rather than oauth2client_) would make this easier.
(``Oic`` is rather sparsely documented, however.)

Use ``preferred_username`` claim, when available, to determine the
default authname for new accounts.

.. _oic: https://pypi.python.org/pypi/oic
.. _oauth2client: https://pypi.python.org/pypi/oauth2client

Integrate with AccountManagerPlugin
===================================

I’m not sure exactly what’s involved, but it would be nice if the
AccountManagerPlugin_ could be used to administer associations between
OIDC subject identifiers and authenticated sessions, etc.

.. _AccountManagerPlugin: https://trac-hacks.org/wiki/AccountManagerPlugin

*******
Authors
*******

`Jeff Dairiki`_

.. _Jeff Dairiki: mailto:dairiki@dairiki.org

.. |version| image::
    https://img.shields.io/pypi/v/trac-oidc.svg
    :target: https://pypi.python.org/pypi/trac-oidc/
    :alt: Latest Version
.. |build status| image::
    https://travis-ci.org/dairiki/trac-oidc.svg?branch=master
    :target: https://travis-ci.org/dairiki/trac-oidc
.. |trac versions| image::
    https://img.shields.io/badge/trac-0.11%2C%200.12%2C%201.0-blue.svg
    :target: http://trac.edgewall.org/
