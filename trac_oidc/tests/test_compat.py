# -*- coding: utf-8 -*-
"""
"""
from __future__ import absolute_import

from bs4 import BeautifulSoup
import pytest
from trac.core import Component
from trac.test import EnvironmentStub
from trac.web.href import Href


@pytest.fixture
def href():
    return Href('http://example.org').test


def parse_tag(tag):
    soup = BeautifulSoup(str(tag))
    elem, = list(soup.children)
    return elem


def test_logout_link(href):
    from ..compat import _logout_link
    link = _logout_link(href, foo='42')
    tag = parse_tag(link)
    assert tag.name == 'a'
    assert tag['href'] == 'http://example.org/test/logout?foo=42'
    assert tag.text == 'Logout'


def test_logout_form(href):
    from ..compat import _logout_form
    form = _logout_form(href, foo='42')
    form = parse_tag(form)
    assert form['action'] == 'http://example.org/test/logout'
    assert form['id'] == 'logout'
    assert form['class'] == ['trac-logout']
    hidden_inputs = dict((input['name'], input['value'])
                         for input in form.find_all('input', type='hidden'))
    assert hidden_inputs == {'foo': '42'}


def test_is_component_enabled():
    from ..compat import is_component_enabled

    class DummyComponent1(Component):
        pass

    class DummyComponent2(Component):
        pass

    env = EnvironmentStub(enable=[DummyComponent2])
    assert not is_component_enabled(env, DummyComponent1)
    assert is_component_enabled(env, DummyComponent2)
