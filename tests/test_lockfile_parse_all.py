"""Tests for lock-file name normalization, PURL building, and the parse_all dispatcher."""

from gitexpose.supply_chain.lockfiles.base import normalize_name, make_purl


def test_normalize_pypi_pep503():
    assert normalize_name("Flask_SQLAlchemy", "PyPI") == "flask-sqlalchemy"
    assert normalize_name("ZopE.Interface", "PyPI") == "zope-interface"


def test_normalize_npm_lowercases():
    assert normalize_name("Lodash", "npm") == "lodash"
    assert normalize_name("@Angular/Core", "npm") == "@angular/core"


def test_make_purl_pypi():
    assert make_purl("requests", "2.31.0", "PyPI") == "pkg:pypi/requests@2.31.0"


def test_make_purl_npm_scoped():
    # scoped npm names encode the scope as a PURL namespace
    purl = make_purl("@angular/core", "17.0.0", "npm")
    assert purl == "pkg:npm/%40angular/core@17.0.0"
