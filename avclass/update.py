#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import sys

from collections import namedtuple
from operator import itemgetter
# from Levenshtein import ratio as levenshtein_ratio

try:
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging, Expansion
except ModuleNotFoundError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import Taxonomy, Tagging, Expansion

# Set logging
log = logging.getLogger(__name__)

# Log warn and above to stderr
formatter = logging.Formatter(u'%(message)s')
handler_stderr = logging.StreamHandler(sys.stderr)
handler_stderr.setLevel(logging.INFO)
handler_stderr.setFormatter(formatter)
root = logging.getLogger()
root.setLevel(logging.DEBUG)
root.addHandler(handler_stderr)

# Threshold for string similarity
# sim_threshold = 0.6

# Relation
Rel = namedtuple('Rel', ['t1', 't2', 't1_num', 't2_num', 
                         'nalias_num', 'talias_num', 'tinv_alias_num'])

class Update:
    """Update Module"""
    def __init__(self, rel_filepath, in_taxonomy, in_tagging, in_expansion, 
                    n, t):
        # Initialize inputs
        self._out_taxonomy = in_taxonomy
        self._out_tagging = in_tagging
        self._out_expansion = in_expansion
        self._n = n
        self._t = t
        # Initialize blacklist
        self.blist = in_taxonomy.platform_tags()
        # Maps src -> cnt
        self.src_map = {}
        # Read relations from file
        self.rel_set = self.read_relations(rel_filepath)

    def num_rules(self):
        """Number of relations"""
        return len(self.rel_set)

    def is_weak_rel(self, rel):
        """Whether input relationship is weak""" 
        return ((int(rel.nalias_num) < self._n) or
                (float(rel.talias_num) < self._t))

    def is_blacklisted_rel(self, rel):
        """Whether input relationship is blacklisted"""
        return (rel.t1 in self.blist) or (rel.t2 in self.blist)

    def is_known_rel(self, rel):
        """Whether input relationship is known"""
        t1 = rel.t1
        t2 = rel.t2
        # Known taxonomy relation
        if self._out_taxonomy.overlaps(t1,t2):
            return True
        # Known expansion rule
        t1_dst = self._out_expansion.get_dst(t1)
        t2_dst = self._out_expansion.get_dst(t2)
        if (t2 in t1_dst) or (t1 in t2_dst):
            return True
        # Known tagging rule
        t1_dst = sorted(self._out_tagging.get_dst(t1))
        t2_dst = sorted(self._out_tagging.get_dst(t2))
        if (t2 in t1_dst) or (t1 in t2_dst):
            return True
        # Known alias in tagging
        if t1_dst and (t1_dst == t2_dst):
            return True
        return False

    def add_tag(self, name, path):
        """Add tag to taxonomy if not in tagging"""
        l = self._out_tagging.get_dst(name)
        if (not l):
            self._out_taxonomy.add_tag(path)

    def add_expansion(self, src, dst_l):
        """Add expansion rule fixing destination if src in tagging"""
        # Select source handling aliases
        l = self._out_tagging.get_dst(src)
        if l:
            new_src = l[0]
        else:
            new_src = src
        # Select destinations removing overlaps with existing rule
        l = self._out_expansion.get_dst(src)
        if l:
            l.extend(dst_l)
            target_l = self._out_taxonomy.remove_overlaps(l)
            self._out_expansion.add_rule(new_src, target_l, True)
        else:
            self._out_expansion.add_rule(new_src, dst_l, True)

    def add_alias(self, src, dst, dst_prefix):
        """Add alias relation to taxonomy, tagging"""
        # If src in tagging, use most popular target
        l = self._out_tagging.get_dst(src)
        target = dst
        if l:
            cnt_max = self.src_map[dst]
            for e in l:
                cnt = self.src_map.get(e, 0)
                if cnt > cnt_max:
                    target = e
        # If dst is in tagging, update tagging rule destination, 
        l = self._out_tagging.get_dst(dst)
        if l:
            target_l = l
        # else add dst to taxonomy
        else:
            target_l = [target]
            self._out_taxonomy.add_tag('%s:%s' % (dst_prefix, dst))
        # Remove src from taxonomy
        self._out_taxonomy.remove_tag(src)
        # Replace tagging rule
        self._out_tagging.add_rule(src, target_l, True)

    def is_expansion_rel(self, rel):
        """Whether input relation implies expansion rule"""
        c1 = self._out_taxonomy.get_category(rel.t1)
        c2 = self._out_taxonomy.get_category(rel.t2)
        return (((c1 == "FAM") and (c2 != c1) and (c2 != "UNK")) or
                ((c1 == "CLASS") and ((c2 == "FILE") or (c2 == "BEH"))) or
                ((c1 == "UNK") and ((c2 == "BEH") or (c2 == "CLASS"))))

    def find_expansions(self):
        """Find expansions among relations"""
        acc = []
        for rel in self.rel_set:
            p1 = self._out_taxonomy.get_path(rel.t1)
            p2 = self._out_taxonomy.get_path(rel.t2)
            log.debug("Processing %s\t%s" % (p1, p2))
            # Ignore relations where t1 is an alias
            l = self._out_tagging.get_dst(rel.t1)
            if l:
                log.debug("Ignoring relation for alias %s" % p1)
                continue
            if self.is_expansion_rel(rel):
                self.add_expansion(rel.t1, [rel.t2])
                acc.append(rel)
        for rel in acc:
            self.rel_set.remove(rel)

    #def is_alias_rel(self, rel):
    #    """Whether input relation implies alias rule"""
    #    c1 = self._out_taxonomy.get_category(rel.t1)
    #    c2 = self._out_taxonomy.get_category(rel.t2)
    #    return (((c1 == "UNK") and (c2 == "FAM")) or
    #            ((c1 == "UNK") and (c2 == "UNK")))


    #def find_aliases(self):
    #    """Find aliases among relations"""
    #    for rel in self.rel_set:
    #        c1 = self._out_taxonomy.get_category(rel.t1)
    #        c2 = self._out_taxonomy.get_category(rel.t2)
    #        if self.is_alias_rel(rel):
    #            self.G.add_node(rel.t1)
    #            self.G.add_node(rel.t2)
    #            self.G.add_edge(rel.t1, rel.t2, score=rel.talias_num)
    #    self.output_components("comp")

    def process_relation(self, rel):
        """Process relation and update taxonomy/tagging correspondingly"""
        # Obtain tag info
        t1 = rel.t1
        t2 = rel.t2
        p1,c1 = self._out_taxonomy.get_info(rel.t1)
        p2,c2 = self._out_taxonomy.get_info(rel.t2)

        log.debug("Processing %s\t%s" % (p1, p2))

        # If both directions strong, then equivalent, i.e., alias
        if (float(rel.tinv_alias_num) >= self._t):
            if (c1 != "UNK") and (c2 == "UNK"):
                prefix = p1[0:p1.rfind(':')]
            elif (c1 == "UNK") and (c2 != "UNK"):
                prefix = p2[0:p2.rfind(':')]
            elif (c1 == "UNK") and (c2 == "UNK"):
                prefix = "FAM"
            elif (c1 == c2):
                prefix = p1[0:p1.rfind(':')]
            else:
                log.warning("Equivalent rule with different categories: %s\t%s"
                                % (p1, p2))
                return -1
            self.add_alias(t1, t2, prefix)
            return 1

        # UNK -> FAM : alias-family
        elif (c1 == "UNK") and (c2 == 'FAM'):
            self.add_alias(t1, t2, "FAM")
            return 1

        # UNK -> CLASS : taxonomy-family
        # Return 0 so that expansion handled at end
        elif (c1 == "UNK") and (c2 == 'CLASS'):
            self.add_tag(t1, 'FAM:%s' % t1)
            return 0

        # UNK -> BEH : taxonomy-family
        # Return 0 so that expansion handled at end
        elif (c1 == "UNK") and (c2 == 'BEH'):
            self.add_tag(t1, 'FAM:%s' % t1)
            return 0

        # UNK -> FILE : taxonomy-file
        elif (c1 == "UNK") and (c2 == 'FILE'):
            self.add_tag(t1, '%s:%s' % (p2, t1))
            return 1

        # UNK -> UNK
        elif (c1 == "UNK") and (c2 == "UNK"):
            self.add_alias(t1, t2, "FAM")
            return 1

        # FAM -> UNK : alias-family
        elif (c1 == "FAM") and (c2 == "UNK"):
            self.add_alias(t1, t2, "FAM")
            return 1

         # FILE -> UNK : alias-file
        elif (c1 == "FILE") and (c2 == "UNK"):
            prefix = p1[0:p1.rfind(':')]
            self.add_alias(t1, t2, prefix)
            return 1

        # Same category : alias
        elif (c1 == "FAM") and (c2 == "FAM"):
        #elif c1 == c2:
            prefix = p2[0:p2.rfind(':')]
            self.add_alias(t1, t2, prefix)
            return 1

        # Target unknown
        elif (c2 == "UNK"):
            # If tokens are similar, likely family aliases
            # log.info("Similarity: %.02f" % levenshtein_ratio(t1, t2))
            # if (levenshtein_ratio(t1, t2) > sim_threshold):
            #     prefix = p1[0:p1.rfind(':')]
            #     self.add_alias(t1, t2, prefix)
            #     return 1
            # else:
            #     return 0
            return 0

        # Default: review taxonomy
        else:
            return 0


    def run(self):
        """Identify updates"""
        num_iter = 0
        while self.rel_set:
            # Do a pass in remaining relations
            cnt = 0
            new_set = set()
            log.debug("[-] %03d Processing relations" % num_iter)
            while self.rel_set:
                rel = self.rel_set.pop()
                # If known relation, continue
                if self.is_known_rel(rel):
                    continue

                # Process relation
                result = self.process_relation(rel)

                if result:
                    cnt += 1
                else:
                    new_set.add(rel)

            # Update relation set
            self.rel_set = new_set

            # If no relations processed, finish
            if cnt == 0:
                break
            else:
                num_iter += 1

        # Find aliases
        # self.find_aliases()

        # Find expansions
        log.debug("[-] Finding expansions")
        self.find_expansions()


    def read_relations(self, filepath):
        """Returns relations in file as a set

           Filters weak and blacklisted relations
        """
        rel_set = set()
        with open(filepath, 'r') as fd:
            for line in fd:
                # Ignore comments
                if line.startswith('#'):
                    continue
                # Parse line
                t1, t2, t1_num, t2_num, nalias_num, talias_num, \
                  tinv_alias_num = line.strip().split('\t')
                # Build relation
                rel = Rel(t1, t2, t1_num, t2_num, nalias_num,
                          talias_num, tinv_alias_num)
                # Ignore weak relations
                if self.is_weak_rel(rel):
                    continue
                # Ignore blacklisted relations
                if self.is_blacklisted_rel(rel):
                    continue
                # Ignore known relations
                # NOTE: commented since we check if a 
                # relation is known before processing it
                #if self.is_known_rel(rel):
                #    continue
                # Add relation to set
                rel_set.add(rel)
                # Add to src_map
                self.src_map[rel.t1] = rel.t1_num
                self.src_map[rel.t2] = rel.t2_num

        return rel_set

    def output_relations(self, filepath):
        """Output relations to given file"""
        fd = open(filepath, 'w')
        fd.write("# t1\tt2\t|t1|\t|t2|\t|t1^t2|\t|t1^t2|/|t1|\t"
                  "|t1^t2|/|t2|\n")
        sorted_rules = sorted(self.rel_set, 
                              key=(lambda r: (
                                self._out_taxonomy.get_category(r.t1),
                                self._out_taxonomy.get_category(r.t2))), 
                              reverse=False)
        for rel in sorted_rules:
            p1,c1 = self._out_taxonomy.get_info(rel.t1)
            p2,c2 = self._out_taxonomy.get_info(rel.t2)
            fd.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\n" %(
                p1, p2, rel.t1_num, rel.t2_num, rel.nalias_num, 
                rel.talias_num, rel.tinv_alias_num))
        fd.close()

    def output_rule_stats(self, fd):
        """Output rule statistics to given file descriptor"""
        # Initialize maps for statistics
        self.dst_map = {}
        self.cat_pairs_map = {}
        # Compute rule statistics
        for rel in self.rel_set:
            c1 = self._out_taxonomy.get_category(rel.t1)
            c2 = self._out_taxonomy.get_category(rel.t2)
            self.cat_pairs_map[(c1,c2)] = self.cat_pairs_map.get((c1,
                                                                  c2), 0) + 1
            self.dst_map[rel.t2] = self.dst_map.get(rel.t2, 0) + 1
        # Output statistics
        cat_pairs = sorted(update.cat_pairs_map.items(), key=itemgetter(1,0), 
                            reverse=True)
        for (c1,c2), cnt in cat_pairs:
            fd.write("%s\t%s\t%03d\n" % (c1, c2, cnt))

        # Print dst statistics
        dst_pairs = sorted(update.dst_map.items(), key=itemgetter(1,0), 
                            reverse=False)
        for dst, cnt in dst_pairs:
            fd.write("%s\t%03d\n" % (taxonomy.get_path(dst), cnt))

    def output(self, out_prefix):
        """Output updated taxonomy/tagging/expansions files"""
        if (not out_prefix):
            tax_filepath = DEFAULT_TAX_PATH
            tag_filepath = DEFAULT_TAG_PATH
            exp_filepath = DEFAULT_EXP_PATH
        else:
            tax_filepath = out_prefix + ".taxonomy"
            tag_filepath = out_prefix + ".tagging"
            exp_filepath = out_prefix + ".expansion"
        self._out_taxonomy.to_file(tax_filepath)
        log.info('[-] Output %d taxonomy tags to %s' % (
                        len(self._out_taxonomy), tax_filepath))
        self._out_tagging.expand_all_destinations()
        self._out_tagging.to_file(tag_filepath)
        log.info('[-] Output %d tagging rules to %s' % (
                        len(self._out_tagging), tag_filepath))
        self._out_expansion.to_file(exp_filepath)
        log.info('[-] Output %d expansion rules to %s' % (
                        len(self._out_expansion), exp_filepath))


def main():
    argparser = argparse.ArgumentParser(
        description='''Given a .alias file from the labeler, 
        generates updates for the taxonomy, tagging, and expansion files.''')

    argparser.add_argument('-alias',
        help='input file with alias from labeler. Mandatory.')

    argparser.add_argument('-n',
        help='Minimum number of times that a pair of tokens have been seen.'
             'Default: 20',
        type=int,
        default=20)

    argparser.add_argument('-t',
        help='Minimum percentage of times two tokens appear together.'
             'Default: 0.94',
        type=float,
        default=0.94)

    argparser.add_argument('-o',
        help='output prefix for files')

    argparser.add_argument('-update',
        action='store_true',
        help='update default taxonomy,tagging,expansion files in place')

    argparser.add_argument('-tag',
        help='file with tagging rules.',
        default = DEFAULT_TAG_PATH)

    argparser.add_argument('-tax',
        help='file with taxonomy.',
        default = DEFAULT_TAX_PATH)

    argparser.add_argument('-exp',
        help='file with expansion rules.',
        default = DEFAULT_EXP_PATH)

    argparser.add_argument('-v', '--verbose',
        action='store_true',
        help='verbose, prints debugging statements.')

    # Parse arguments
    args = argparser.parse_args()

    # Check we have the input
    if not args.alias:
        log.error('[-] Please provide an alias file with -alias')
        exit(1)

    # Set logging level
    if (args.verbose):
        handler_stderr.setLevel(logging.DEBUG)

    # Set output prefix
    if args.o:
        out_prefix = args.o
    else:
        out_prefix = os.path.splitext(args.alias)[0]

    # Read taxonomy
    taxonomy = Taxonomy(args.tax)
    log.info('[-] Read %d taxonomy tags from %s' % (
                        len(taxonomy), args.tax))

    # Read tagging rules
    tagging = Tagging(args.tag)
    log.info('[-] Read %d tagging rules from %s' % (
                        len(tagging), args.tag))

    # Read expansion rules
    expansion = Expansion(args.exp)
    log.info('[-] Read %d expansion rules from %s' % (
                        len(expansion), args.exp))

    # Build update object
    update = Update(args.alias, taxonomy, tagging, expansion, args.n, args.t)

    log.info('[-] Processing %d relations satisfying t>=%.2f n>=%d' % (
                        update.num_rules(), args.t, args.n))

    # Output initial rules
    update.output_relations(out_prefix + ".orig.rules")

    # Output initial rules statistics
    # update.output_rule_stats(sys.stderr)

    # Process relations
    update.run()

    # Output updated taxonomy,tagging,expansion
    if args.update:
        update.output(None)
    else:
        update.output(out_prefix)

    # Output final rules
    update.output_relations(out_prefix + ".final.rules")

if __name__ == "__main__":
    main()

