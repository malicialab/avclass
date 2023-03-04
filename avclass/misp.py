#!/usr/bin/env python3

import argparse
import json
import os
import uuid
import sys

try:
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging
except ModuleNotFoundError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging

default_file = "avclass.json"

class Misp:
    """A class to produce the MISP taxonomy"""
    def __init__(self, tax_filepath, tag_filepath):
        self.taxonomy = Taxonomy(tax_filepath)
        self.tagging = Tagging(tag_filepath)

    def uuid_gen(self, tag, prefix='avclass:'):
        """Generate a UUID for given tag"""
        return str(uuid.uuid3(uuid.NAMESPACE_DNS, prefix + tag))

    def output_galaxy_file(self, filepath, version):
        """Output MSIP galaxy to given file"""
        galaxy_uuid = uuid.uuid3(uuid.NAMESPACE_DNS,'avclass_galaxy')
        galaxy_header = {
          "description" : "A malware galaxy from AVClass taxonomy",
          "name" : "AVClass",
          "namespace" : "misp",
          "type" : "avclass",
          "uuid" : str(galaxy_uuid),
          "version" : version
        }
        with open(filepath,'w') as fd:
            fd.write(json.dumps(galaxy_header,indent=2,sort_keys=True))

    def output_cluster_file(self, filepath, version):
        """Output MSIP cluster to given file"""
        entries = []
        dst_map = self.tagging.build_synonymn_map()
        for tag in self.taxonomy:
            # Ignore generics
            if tag.cat == 'GEN':
                continue
            # Get synonyms
            synonyms = dst_map.get(tag.name, {})
            # Build entry
            tag_uuid = self.uuid_gen(tag.name)
            entry_dict = {
                'description' : tag.path,
                'meta' : {
                    'refs' : [],
                    'synonyms' : sorted(synonyms),
                    'type' : []
                },
                'uuid' : tag_uuid,
                'value' : tag.name
            }
            entries.append(entry_dict)
        cluster_uuid = uuid.uuid3(uuid.NAMESPACE_DNS,'avclass_cluster')
        cluster_header = {
            'authors' : ['MaliciaLab'],
            'category' : 'tool',
            'description' : 'AVClass cluster',
            'name' : 'AVClass',
            'source' : 'AVClass',
            'type' : 'avclass',
            'uuid' : str(cluster_uuid),
            'values' : entries,
            'version' : version
        }
        with open(filepath,'w') as fd:
            fd.write(json.dumps(cluster_header,indent=2,sort_keys=True))

def main():
    argparser = argparse.ArgumentParser(
        description='Creates MISP taxonomy.')

    argparser.add_argument('-tag',
        help='tagging file',
        default=DEFAULT_TAG_PATH)

    argparser.add_argument('-tax',
        help='taxonomy file',
        default=DEFAULT_TAX_PATH)

    argparser.add_argument('-o',
        help='output directory',
        default="./")

    argparser.add_argument('-v',
        help='version')

    # Parse arguments
    args = argparser.parse_args()

    # Build MISP object
    misp = Misp(args.tax, args.tag)

    # Create output directories if needed
    misp_dir = "%s/misp/" % args.o
    if (not os.path.exists(misp_dir)):
        os.makedirs(misp_dir)
    galaxy_dir = "%s/galaxy" % misp_dir
    if (not os.path.exists(galaxy_dir)):
        os.makedirs(galaxy_dir)
    cluster_dir = "%s/cluster" % misp_dir
    if (not os.path.exists(cluster_dir)):
        os.makedirs(cluster_dir)

    # Output galaxy file
    galaxy_filepath = "%s/%s" % (galaxy_dir, default_file)
    misp.output_galaxy_file(galaxy_filepath, args.v)

    # Output cluster file
    cluster_filepath = "%s/%s" % (cluster_dir, default_file)
    misp.output_cluster_file(cluster_filepath, args.v)

if __name__ == "__main__":
    main()

