"""Python module containing the version string of paranoid_crypto library."""

from paranoid_crypto.lib import resources

_PATH_VERSION = "VERSION"
__version__ = resources.GetParanoidResource(_PATH_VERSION).decode().strip()
