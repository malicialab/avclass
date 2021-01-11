import argparse

from avclass import util


def validate_files():
    parser = argparse.ArgumentParser(description='Checks format of files Tagging, Expansion and Taxonomy.')
    parser.add_argument('-exp',
                        help='expansion file',
                        default=util.DEFAULT_EXP_PATH)
    parser.add_argument('-tag',
                        help='tagging file',
                        default=util.DEFAULT_TAG_PATH)
    parser.add_argument('-tax',
                        help='taxonomy file',
                        default=util.DEFAULT_TAX_PATH)

    args = parser.parse_args()

    taxonomy = util.validate_taxonomy(args.tax)
    util.validate_tagging(args.tag, taxonomy)
    util.validate_expansion(args.exp, taxonomy)
