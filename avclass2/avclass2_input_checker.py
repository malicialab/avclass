#!/usr/bin/env python
'''
AVClass2 input checker
'''

import os
import sys
import argparse
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.join(script_dir, 'lib/'))
from avclass2_common import Taxonomy, Tagging, Expansion

default_tag_file = "data/default.tagging"
default_tax_file = "data/default.taxonomy"
default_exp_file = "data/default.expansion"

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(prog='input_checker',
        description='Checks format of files Tagging, Expansion and Taxonomy.')

    argparser.add_argument('-tag',
        help='tagging file',
        default=default_tag_file)

    argparser.add_argument('-tax',
        help='taxonomy file',
        default=default_tax_file)

    argparser.add_argument('-exp',
        help='expansion file',
        default=default_exp_file)

    # Parse arguments
    args = argparser.parse_args()

    # Normalize taxonomy
    taxonomy = Taxonomy(args.tax)
    taxonomy.to_file(args.tax)
    sys.stdout.write('[-] Normalized %d tags in taxonomy %s\n' % (
                        len(taxonomy), args.tax))

    # Normalize tagging rules
    tagging = Tagging(args.tag)
    tagging.validate(taxonomy)
    # tagging.expand_all_destinations()
    tagging.to_file(args.tag)
    sys.stdout.write('[-] Normalized %d tagging rules in %s\n' % (
                        len(tagging), args.tag))

    # Normalize expansion rules
    expansion = Expansion(args.exp)
    expansion.validate(taxonomy)
    expansion.to_file(args.exp)
    sys.stdout.write('[-] Normalized %d expansion rules in %s\n' % (
                        len(expansion), args.exp))

