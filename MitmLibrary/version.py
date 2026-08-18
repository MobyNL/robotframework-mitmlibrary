"""Single source of the library version, read from the installed package metadata."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    VERSION = _version("robotframework-mitmlibrary")
except PackageNotFoundError:  # running from a source checkout without an install
    VERSION = "0.0.0.dev0"
