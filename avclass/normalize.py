#!/usr/bin/env python3

import argparse
import os
import sys

try:
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging, Expansion
except ModuleNotFoundError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging, Expansion

def main():
    argparser = argparse.ArgumentParser(prog='input_checker',
        description='Checks format of files Tagging, Expansion and Taxonomy.')

    argparser.add_argument('-tag',
        help='tagging file',
        default=DEFAULT_TAG_PATH)

    argparser.add_argument('-tax',
        help='taxonomy file',
        default=DEFAULT_TAX_PATH)

    argparser.add_argument('-exp',
        help='expansion file',
        default=DEFAULT_EXP_PATH)

    # Parse arguments
    args = argparser.parse_args()

    # Normalize taxonomy
    taxonomy = Taxonomy(args.tax)
    taxonomy.to_file(args.tax)
    print('[-] Normalized %d tags in taxonomy %s' % (
                        len(taxonomy), args.tax))

    # Normalize tagging rules
    tagging = Tagging(args.tag)
    tagging.validate(taxonomy)
    # tagging.expand_all_destinations()
    tagging.to_file(args.tag)
    print('[-] Normalized %d tagging rules in %s' % (
                        len(tagging), args.tag))

    # Normalize expansion rules
    expansion = Expansion(args.exp)
    expansion.validate(taxonomy)
    expansion.to_file(args.exp)
    print('[-] Normalized %d expansion rules in %s' % (
                        len(expansion), args.exp))

if __name__ == "__main__":
    main()

