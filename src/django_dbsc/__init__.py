from importlib.metadata import version

# Read from the installed metadata, so pyproject.toml stays the only place the version is written.
__version__ = version("django-dbsc")
