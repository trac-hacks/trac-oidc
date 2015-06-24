# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from distutils.version import LooseVersion

from genshi.builder import tag
import trac
from trac.util.translation import _


def _logout_link(href, **kwargs):
    '''Return "Logout" link

    This is a simple link, as used by trac < 1.0.2.

    '''
    return tag.a(_('Logout'), href=href('logout', **kwargs))


def _logout_form(href, **kwargs):
    '''Return "Logout" "link"

    This version returns a form — styled to look like a link — as used
    by trac >= 1.0.2 (for CSRF protection.)  Unfortunately, this does
    not render nicely in older tracs, since ``trac.css`` does not
    include the proper styling for ``form.trac-logout``.

    '''
    fields = [tag.button(_('Logout'), name='logout', type='submit')]
    for name, value in kwargs.items():
        fields.append(tag.input(type='hidden', name=name, value=value))
    return tag.form(tag.div(*fields),
                    action=href('logout'), id='logout', class_='trac-logout')


# Recent versions of trac use a logout form for csrf protection.  If
# trac.css supports it, we should too.
LOGOUT_REQUIRES_POST = LooseVersion(trac.__version__) >= '1.0.2'
logout_link = _logout_form if LOGOUT_REQUIRES_POST else _logout_link


def is_component_enabled(env, cls):
    """ Determine whether a trac component is enabled.

    """
    # We would like to use env.is_enabled(cls) to do this,
    # however, trac 0.11 does not have ComponentManager.is_enabled().
    # So instead, rely on ComponentManager.__getitem__(), which does
    # have the same logic in it.
    return env[cls] is not None
