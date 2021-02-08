import argparse
import logging

from avclass import util
from avclass.common import Taxonomy, Translation, Expansion
from typing import AnyStr


logger = logging.getLogger(__name__)

__all__ = (
    "validate_expansion",
    "validate_tagging",
    "validate_taxonomy",
)


def validate_taxonomy(path: AnyStr):
    """
    Validate and normalize a Taxonomy created from ``path``

    :param path: Location on disk of a Taxonomy file
    :return: Taxonomy object
    """
    taxonomy = Taxonomy(path)
    taxonomy.to_file(path)

    print("[-] Normalized %d tags in taxonomy %s" % (len(taxonomy), path))
    logger.info("[-] Normalized %d tags in taxonomy %s" % (len(taxonomy), path))

    return taxonomy


def validate_tagging(path: AnyStr, taxonomy: Taxonomy):
    """
    Validate and normalize Tagging created from ``path`` and verified against ``taxonomy``

    :param path: Location on disk of a Tagging file
    :param taxonomy: Valid Taxonomy object
    :return: None
    """
    tagging = Translation(path)
    tagging.validate(taxonomy)
    # tagging.expand_all_destinations()
    tagging.to_file(path)

    print("[-] Normalized %d tagging rules in %s" % (len(tagging), path))
    logger.info("[-] Normalized %d tagging rules in %s" % (len(tagging), path))


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

    print("[-] Normalized %d expansion rules in %s" % (len(expansion), path))
    logger.info("[-] Normalized %d expansion rules in %s" % (len(expansion), path))


def validate_files():
    parser = argparse.ArgumentParser(
        description="Checks format of files Tagging, Expansion and Taxonomy."
    )
    parser.add_argument("-exp", help="expansion file", default=util.DEFAULT_EXP_PATH)
    parser.add_argument("-tag", help="tagging file", default=util.DEFAULT_TAG_PATH)
    parser.add_argument("-tax", help="taxonomy file", default=util.DEFAULT_TAX_PATH)

    args = parser.parse_args()

    taxonomy = validate_taxonomy(args.tax)
    validate_tagging(args.tag, taxonomy)
    validate_expansion(args.exp, taxonomy)


if __name__ == "__main__":
    validate_files()
