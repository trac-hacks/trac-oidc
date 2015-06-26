# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
"""
from __future__ import absolute_import

import mock
import pytest


class Test_strings_differ(object):
    def call_it(self, string1, string2):
        from ..util import strings_differ
        return strings_differ(string1, string2)

    def test_strings_equal(self):
        assert not self.call_it('foobar', u'foobar')

    def test_strings_differ(self):
        assert self.call_it('foobar', 'foobaz')

    def test_strings_different_length(self):
        assert self.call_it('foobar', 'fooba')


class TestDeferredMapping(object):
    def make_one(self, data=None, callback=None):
        from ..util import DeferredMapping
        return DeferredMapping(data, callback)

    def test_getitem(self):
        data = {'x': 42}
        callback = lambda: {'y': 'foo'}
        mapping = self.make_one(data, callback)
        assert mapping['x'] == 42
        assert mapping['y'] == 'foo'
        with pytest.raises(KeyError):
            mapping['z']

    def test_iter(self):
        data = {'x': 42}
        callback = lambda: {'y': 'foo'}
        mapping = self.make_one(data, callback)
        assert set(mapping) == set(['x', 'y'])

    def test_len(self):
        data = {'x': 42}
        callback = lambda: {'y': 'foo'}
        mapping = self.make_one(data, callback)
        assert len(mapping) == 2

    def test_callback_not_called_until_needed(self):
        data = {'x': 42}
        callback = mock.Mock(return_value={})
        mapping = self.make_one(data, callback)
        assert mapping['x'] == 42
        assert callback.call_count == 0

    def test_callback_not_called_more_than_once(self):
        data = {}
        callback = mock.Mock(return_value={})
        mapping = self.make_one(data, callback)
        for key in 'x', 'y', 'z':
            assert mapping.get(key) is None
        assert callback.call_count == 1

    def test_callback_returns_none(self):
        data = {}
        callback = lambda: None
        mapping = self.make_one(data, callback)
        assert list(mapping) == []
