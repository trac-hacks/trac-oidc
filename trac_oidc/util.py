# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from collections import Mapping


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


class DeferredMapping(Mapping):
    """ This is a mapping for which the computation of some or all of its
    items is deferred.

    The mapping contains the union of items specified by ``data``
    and the return value of ``callback()``.  The callback is not called
    until necessary.

    """
    def __init__(self, data=None, callback=None):
        self.data = data or {}
        self.callback = callback

    def _undefer(self):
        if self.callback:
            new_data = self.callback()
            self.callback = None
            if new_data is not None:
                self.data.update(new_data)

    def __getitem__(self, key):
        try:
            return self.data[key]
        except KeyError:
            self._undefer()
            return self.data[key]

    def __iter__(self):
        self._undefer()
        return iter(self.data)

    def __len__(self):
        self._undefer()
        return len(self.data)
