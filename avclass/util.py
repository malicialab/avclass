import atexit
import logging
import pkg_resources

from avclass import data
from avclass.common import Taxonomy, Tagging, Expansion

from typing import AnyStr


__all__ = (
    'DEFAULT_EXP_PATH',
    'DEFAULT_TAG_PATH',
    'DEFAULT_TAX_PATH',
    'validate_expansion',
    'validate_tagging',
    'validate_taxonomy',
)


logger = logging.getLogger(__name__)

DEFAULT_EXP = "default.expansion"
DEFAULT_TAG = "default.tagging"
DEFAULT_TAX = "default.taxonomy"

DEFAULT_TAG_PATH = None
DEFAULT_TAX_PATH = None
DEFAULT_EXP_PATH = None

if pkg_resources.resource_exists(data, DEFAULT_EXP):
    DEFAULT_EXP_PATH = pkg_resources.resource_filename(data, DEFAULT_EXP)

if pkg_resources.resource_exists(data, DEFAULT_TAG):
    DEFAULT_TAG_PATH = pkg_resources.resource_filename(data, DEFAULT_TAG)

if pkg_resources.resource_exists(data, DEFAULT_TAX):
    DEFAULT_TAX_PATH = pkg_resources.resource_filename(data, DEFAULT_TAX)

atexit.register(pkg_resources.cleanup_resources)


def validate_taxonomy(path: AnyStr):
    """
    Validate and normalize a Taxonomy created from ``path``

    :param path: Location on disk of a Taxonomy file
    :return: Taxonomy object
    """
    taxonomy = Taxonomy(path)
    taxonomy.to_file(path)

    logger.info('[-] Normalized %d tags in taxonomy %s\n' % (len(taxonomy), path))

    return taxonomy


def validate_tagging(path: AnyStr, taxonomy: Taxonomy):
    """
    Validate and normalize Tagging created from ``path`` and verified against ``taxonomy``

    :param path: Location on disk of a Tagging file
    :param taxonomy: Valid Taxonomy object
    :return: None
    """
    tagging = Tagging(path)
    tagging.validate(taxonomy)
    # tagging.expand_all_destinations()
    tagging.to_file(path)

    logger.info('[-] Normalized %d tagging rules in %s\n' % (len(tagging), path))


def validate_expansion(path: AnyStr, taxonomy: Taxonomy):
    """
    Validate and normalize Expansion created from ``path`` and verified against ``taxonomy``

    :param path: Location on disk of an Expansion file
    :param taxonomy: Valid Taxonomy object
    :return: None
    """
    expansion = Expansion(path)
    expansion.validate(taxonomy)
    expansion.to_file(path)

    logger.info('[-] Normalized %d expansion rules in %s\n' % (len(expansion), path))
