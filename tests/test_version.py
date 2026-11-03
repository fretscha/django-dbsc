from importlib.metadata import version

import django_dbsc


def test_version_comes_from_package_metadata():
    # One source of truth: pyproject.toml. The release workflow checks the tag against it.
    assert django_dbsc.__version__ == version("django-dbsc")
