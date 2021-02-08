import atexit
import pkg_resources

from avclass import data


__all__ = (
    "DEFAULT_EXP_PATH",
    "DEFAULT_TAG_PATH",
    "DEFAULT_TAX_PATH",
)

RESOURCE_EXP = "default.expansion"
RESOURCE_TAG = "default.tagging"
RESOURCE_TAX = "default.taxonomy"

DEFAULT_TAG_PATH = None
DEFAULT_TAX_PATH = None
DEFAULT_EXP_PATH = None

if pkg_resources.resource_exists(data.__name__, RESOURCE_EXP):
    DEFAULT_EXP_PATH = pkg_resources.resource_filename(data.__name__, RESOURCE_EXP)

if pkg_resources.resource_exists(data.__name__, RESOURCE_TAG):
    DEFAULT_TAG_PATH = pkg_resources.resource_filename(data.__name__, RESOURCE_TAG)

if pkg_resources.resource_exists(data.__name__, RESOURCE_TAX):
    DEFAULT_TAX_PATH = pkg_resources.resource_filename(data.__name__, RESOURCE_TAX)

atexit.register(pkg_resources.cleanup_resources)
