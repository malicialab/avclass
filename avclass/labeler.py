#!/usr/bin/env python3

import argparse
import gzip
import json
import logging
import os
import string
import sys
import traceback

from operator import itemgetter

try:
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import AvLabels, Taxonomy, SampleInfo
    from avclass import evaluate as ec
except ModuleNotFoundError:
    # Helps find the avclasses when run from console
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import AvLabels, Taxonomy, SampleInfo
    from avclass import evaluate as ec

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

# Default hash to name samples
default_hash_type = "md5"

def guess_hash(h):
    """Guess the hash type of input string"""
    hlen = len(h)
    if hlen == 32:
        return 'md5'
    elif hlen == 40:
        return 'sha1'
    elif hlen == 64:
        return 'sha256'
    else:
        return None

def read_avs(filepath):
    """Read AV engine set from given file"""
    with open(filepath) as fd:
        avs = set(map(str.strip, fd.readlines()))
    return avs

def read_gt(filepath):
    """Read ground truth from given file"""
    gt_dict = {}
    with open(filepath, 'r') as fd:
        for line in fd:
            gt_hash, family = map(str, line.strip().split('\t', 1))
            gt_dict[gt_hash] = family
    return gt_dict

class FileLabeler:
    """Class to extract tags from files"""
    def __init__(self,
        out_fd,
        tag_file = DEFAULT_TAG_PATH,
        exp_file = DEFAULT_EXP_PATH,
        tax_file = DEFAULT_TAX_PATH,
        av_l = None,
        gt_dict = None,
        hash_type = default_hash_type,
        collect_relations = False,
        collect_vendor_info = False,
        collect_stats = False,
        output_all_tags = False,
        output_pup_flag = False,
        output_vt_tags = False
    ):
        """Initialize labeler"""
        # Create AvLabels object
        self.av_labels = AvLabels(tag_file, exp_file, tax_file, av_l=av_l)
        # Store inputs
        self.out_fd = out_fd
        self.gt_dict = gt_dict
        self.hash_type = hash_type
        self.collect_relations = collect_relations
        self.collect_vendor_info = collect_vendor_info
        self.collect_stats = collect_stats
        self.output_all_tags = output_all_tags
        self.output_pup_flag = output_pup_flag
        self.output_vt_tags = output_vt_tags
        # Initialize state
        self.first_token_dict = {}
        self.token_count_map = {}
        self.pair_count_map = {}
        self.vt_all = 0
        self.avtags_dict = {}
        self.stats = {
            'samples': 0,
            'noscans': 0,
            'tagged': 0,
            'maltagged': 0,
            'FAM': 0,
            'CLASS': 0,
            'BEH': 0,
            'FILE': 0,
            'UNK': 0
        }

    @staticmethod
    def get_sample_info_lb(vt_rep):
        """Parse sample information from basic report"""
        return SampleInfo(vt_rep['md5'], vt_rep['sha1'], vt_rep['sha256'],
                          vt_rep['av_labels'], [])

    @staticmethod
    def get_sample_info_vt_v2(vt_rep):
        """Parse sample information from VT v2 report"""
        label_pairs = []
        # Obtain scan results, if available
        try:
            scans = vt_rep['scans']
            md5 = vt_rep['md5']
            sha1 = vt_rep['sha1']
            sha256 = vt_rep['sha256']
        except KeyError:
            return None
        # Obtain labels from scan results
        for av, res in scans.items():
            if res['detected']:
                label = res['result']
                clean_label = ''.join(filter(
                                  lambda x: x in string.printable,
                                    label)).strip()
                label_pairs.append((av, clean_label))
        # Obtain VT tags, if available
        vt_tags = vt_rep.get('tags', [])

        return SampleInfo(md5, sha1, sha256, label_pairs, vt_tags)

    @staticmethod
    def get_sample_info_vt_v3(vt_rep):
        """Parse sample information from VT v3 report"""
        # VT file reports in APIv3 contain all info under 'data'
        # but reports from VT file feed (also APIv3) don't have it
        # Handle both cases silently here
        if 'data' in vt_rep:
            vt_rep = vt_rep['data']
        label_pairs = []
        # Obtain scan results, if available
        try:
            scans = vt_rep['attributes']['last_analysis_results']
            md5 = vt_rep['attributes']['md5']
            sha1 = vt_rep['attributes']['sha1']
            sha256 = vt_rep['attributes']['sha256']
        except KeyError:
            return None
        # Obtain labels from scan results
        for av, res in scans.items():
            label = res['result']
            if label is not None:
                clean_label = ''.join(filter(
                                  lambda x: x in string.printable,
                                    label)).strip()
                label_pairs.append((av, clean_label))
        # Obtain VT tags, if available
        vt_tags = vt_rep['attributes'].get('tags', [])

        return SampleInfo(md5, sha1, sha256, label_pairs, vt_tags)

    @staticmethod
    def get_sample_info_opswat_md(vt_rep):
        """Parse sample information from OPSWAT MetaDefender report"""
        try:
            scans = vt_rep["scan_results"]["scan_details"]
            md5 = vt_rep["file_info"]["md5"]
            sha1 = vt_rep["file_info"]["sha1"]
            sha256 = vt_rep["file_info"]["sha256"]
        except KeyError:
            return None
        # Obtain labels from scan results
        label_pairs = []
        for av, res in scans.items():
            label = res["threat_found"]
            if label is not None and res["scan_result_i"] == 1:
                clean_label = "".join(
                    filter(lambda x: x in string.printable, label)
                ).strip()
                label_pairs.append((av, clean_label))

        return SampleInfo(md5, sha1, sha256, label_pairs, [])

    def open_file(self, filepath):
        """Guess filetype and return file descriptor to file"""
        # Check if file is gzipped by opening it as raw data
        with open(filepath, "rb") as test_fd:
            is_gzipped = test_fd.read(2) == b"\x1f\x8b"
        # Open file correctly
        if is_gzipped:
            fd = gzip.open(filepath, "rt")
        else:
            fd = open(filepath, "r")
        # Read first line
        first_line = fd.readline().strip('\n')
        # Parse line
        report = json.loads(first_line)
        # Check type by parsing the first line
        sample_info = self.get_sample_info_vt_v3(report)
        if sample_info is not None:
            itype = "vt3"
            get_sample_info_fun = self.get_sample_info_vt_v3
        else:
            sample_info = self.get_sample_info_vt_v2(report)
            if sample_info is not None:
                itype = "vt2"
                get_sample_info_fun = self.get_sample_info_vt_v2
            else:
                sample_info = self.get_sample_info_opswat_md(report)
                if sample_info is not None:
                    itype = "md"
                    get_sample_info_fun = self.get_sample_info_opswat_md
                else:
                    itype = "lb"
                    get_sample_info_fun = self.get_sample_info_lb
        # Set file pointer to beginning again
        fd.seek(0, 0)
        # Return file descriptor and type
        return fd, itype, get_sample_info_fun

    def process_line(self, line, get_sample_info):
        """Tag report line and output results"""
        # If blank line, skip
        if line == '\n':
            return

        # Debug info
        if (self.vt_all > 0) and (self.vt_all % 100 == 0):
            sys.stderr.write('\r[-] %d reports read' % self.vt_all)
            sys.stderr.flush()
        self.vt_all += 1

        # Read JSON line
        vt_rep = json.loads(line)

        # Extract sample info
        sample_info = get_sample_info(vt_rep)

        # If no sample info, log error and continue
        if sample_info is None:
            try:
                name = vt_rep['md5']
                log.warning('\nNo scans for %s' % name)
            except KeyError:
                log.warning('\nCould not process: %s' % line)
            self.stats['noscans'] += 1
            return

        # Sample's name is selected hash type (md5 by default)
        name = getattr(sample_info, self.hash_type)

        # If the VT report has no AV labels, output and continue
        if not sample_info.labels:
            self.out_fd.write('%s\t-\t[]\n' % (name))
            return

        # Compute VT_Count (using list of AV engines if provided)
        vt_count = self.av_labels.get_sample_vt_count(sample_info)

        # Get the distinct tokens from all the av labels in the report
        # And print them. 
        try:
            av_tmp = self.av_labels.get_sample_tags(sample_info,
                                          expand=(not self.collect_relations))
            tags = self.av_labels.rank_tags(av_tmp)

            # AV VENDORS PER TOKEN
            if self.collect_vendor_info:
                for t in av_tmp:
                    tmap = self.avtags_dict.get(t, {})
                    for av in av_tmp[t]:
                        ctr = tmap.get(av, 0)
                        tmap[av] = ctr + 1
                    self.avtags_dict[t] = tmap

            if self.collect_relations:
                prev_tokens = set()
                for entry in tags:
                    curr_tok = entry[0]
                    curr_count = self.token_count_map.get(curr_tok, 0)
                    self.token_count_map[curr_tok] = curr_count + 1
                    for prev_tok in prev_tokens:
                        if prev_tok < curr_tok:
                            pair = (prev_tok,curr_tok)
                        else:
                            pair = (curr_tok,prev_tok)
                        pair_count = self.pair_count_map.get(pair, 0)
                        self.pair_count_map[pair] = pair_count + 1
                    prev_tokens.add(curr_tok)

            # Collect stats
            # FIX: should iterate once over tags, 
            # for both stats and collect_relations
            if tags:
                self.stats["tagged"] += 1
                if self.collect_stats:
                    if (vt_count > 3):
                        self.stats["maltagged"] += 1
                        cat_map = {'FAM': False, 'CLASS': False,
                                   'BEH': False, 'FILE': False, 'UNK':
                                       False}
                        for t in tags:
                            path, cat = self.av_labels.taxonomy.get_info(t[0])
                            cat_map[cat] = True
                        for c in cat_map:
                            if cat_map[c]:
                                self.stats[c] += 1

            # Check if sample is PUP, if requested
            if self.output_pup_flag:
                is_pup = self.av_labels.is_pup(tags, self.av_labels.taxonomy)
            else:
                is_pup = None

            # Select family for sample
            fam = "SINGLETON:" + name
            for (t,s) in tags:
                cat = self.av_labels.taxonomy.get_category(t)
                if (cat == "UNK") or (cat == "FAM"):
                    fam = t
                    break

            # Get ground truth family, if available
            if self.gt_dict is not None:
                self.first_token_dict[name] = fam
                gt_family = self.gt_dict.get(name, "")
            else:
                gt_family = None

            # Get VT tags, if requested
            if self.output_vt_tags:
                vt_tags = sample_info.vt_tags
            else:
                vt_tags = None

            # Output sample information
            if self.output_all_tags:
                self.output_with_tags_format(name, vt_count, tags)
            else:
                self.output_with_family_format(name, fam, gt_family, 
                                                is_pup, vt_tags)
        except:
            traceback.print_exc(file=sys.stderr)
            return

    def process_file(self, ifile):
        # Open file
        fd, itype, get_sample_info = self.open_file(ifile)

        # Debug info, file processed
        log.info('[-] Processing input file %s (%s)' % (ifile, itype))

        # Process all lines in file
        for line in fd:
            self.process_line(line, get_sample_info)

        # Debug info
        sys.stderr.write('\r[-] %d reports read' % self.vt_all)
        sys.stderr.flush()
        sys.stderr.write('\n')

        # Close file
        fd.close()

        # Print statistics
        log.info(
                "[-] Samples: %d NoScans: %d NoTags: %d GroundTruth: %d" % (
                    self.vt_all,
                    self.stats['noscans'],
                    self.vt_all - self.stats['tagged'], 
                    len(self.gt_dict) if self.gt_dict else 0)
        )

    def compute_accuracy(self):
        """Compute accuracy statistics using ground truth"""
        return ec.eval_precision_recall_fmeasure(self.gt_dict,
                                                 self.first_token_dict)

    def format_tag_pairs(self, tag_l):
        """Return ranked tags as string"""
        if not tag_l:
            return ""
        if self.av_labels.taxonomy is not None:
            p = self.av_labels.taxonomy.get_path(tag_l[0][0])
        else:
            p = tag_l[0][0]
        out = "%s|%d" % (p, tag_l[0][1])
        for (t,s) in tag_l[1:]:
            if self.av_labels.taxonomy is not None:
                p = self.av_labels.taxonomy.get_path(t)
            else:
                p = t
            out += ",%s|%d" % (p, s)
        return out

    def output_with_family_format(self, name, family, gt_family, 
                                  is_pup, vt_tags):
        """Output sample family results"""
        # Prepare is_pup_str
        if is_pup is not None:
            is_pup_str = "\t1" if is_pup else "\t0"
        else:
            is_pup_str = ""
        # Prepare ground truth family
        if gt_family is not None:
            gt_family = '\t' + gt_family
        else:
            gt_family = ""
        # Prepare vt tags
        vtt = '\t' + ','.join(vt_tags) if vt_tags else ""
        # Write info
        self.out_fd.write('%s\t%s%s%s%s\n' % 
                            (name, family, gt_family, is_pup_str, vtt))

    def output_with_tags_format(self, name, vt_count, tags):
        """Output sample tags"""
        # Prepare tags
        tag_str = self.format_tag_pairs(tags)
        # Write info
        self.out_fd.write('%s\t%d\t%s\n' % (name, vt_count, tag_str))

    def output_relations(self, filepath):
        """Output collected relations to given file"""
        # Open file
        fd = open(filepath, 'w+')
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(
            self.pair_count_map.items(), key=itemgetter(1))

        # Output header line
        fd.write("# t1\tt2\t|t1|\t|t2|\t"
                       "|t1^t2|\t|t1^t2|/|t1|\t|t1^t2|/|t2|\n")
        # Compute token pair statistic and output to alias file
        for (t1, t2), c in sorted_pairs:
            n1 = self.token_count_map[t1]
            n2 = self.token_count_map[t2]
            if (n1 < n2):
                x = t1
                y = t2
                xn = n1
                yn = n2
            else:
                x = t2
                y = t1
                xn = n2
                yn = n1
            f = float(c) / float(xn)
            finv = float(c) / float(yn)
            x = self.av_labels.taxonomy.get_path(x)
            y = self.av_labels.taxonomy.get_path(y)
            fd.write("%s\t%s\t%d\t%d\t%d\t%0.2f\t%0.2f\n" % (
                x, y, xn, yn, c, f, finv))
        # Close file
        fd.close()

    def output_stats(self, filepath):
        fd = open(filepath, 'w')
        num_samples = self.vt_all
        fd.write('Samples: %d\n' % num_samples)
        num_tagged = self.stats['tagged']
        frac = float(num_tagged) / float(num_samples) * 100
        fd.write('Tagged (all): %d (%.01f%%)\n' % (num_tagged, frac))
        num_maltagged = self.stats['maltagged']
        frac = float(num_maltagged) / float(num_samples) * 100
        fd.write('Tagged (VT>3): %d (%.01f%%)\n' % (num_maltagged, frac))
        for c in ['FILE','CLASS','BEH','FAM','UNK']:
            count = self.stats[c]
            frac = float(count) / float(num_maltagged) * 100
            fd.write('%s: %d (%.01f%%)\n' % (c, self.stats[c], frac))
        fd.close()

    def output_vendor_info(self, filepath):
        fd = open(filepath, 'w')
        for t in sorted(self.avtags_dict.keys()):
            fd.write('%s\t' % t)
            pairs = sorted(self.avtags_dict[t].items(),
                            key=lambda pair : pair[1],
                            reverse=True)
            for pair in pairs:
                fd.write('%s|%d,' % (pair[0], pair[1]))
            fd.write('\n')
        fd.close()


def main():
    # Parse arguments
    args, ifile_l = parse_args()

    # Read AV engines to be used, if provided
    engine_l = read_avs(args.av) if args.av else None

    # Read ground truth, if provided
    gt_dict = read_gt(args.gt) if args.gt else None

    # Select hash type used to name samples
    if args.gt:
        hash_type = guess_hash(list(gt_dict.keys())[0])
    elif args.hash:
        hash_type = args.hash 
    else:
        hash_type = default_hash_type

    # Set output descriptor
    if args.o:
        out_fd = open(args.o, 'w', encoding='utf-8')
    else:
        out_fd = sys.stdout

    # Create file labeler
    labeler = FileLabeler(
        out_fd,
        tag_file = args.tag,
        exp_file = args.exp,
        tax_file = args.tax,
        av_l = engine_l,
        gt_dict = gt_dict,
        hash_type = hash_type,
        collect_relations = args.aliasdetect,
        collect_vendor_info = args.avtags,
        collect_stats = args.stats,
        output_all_tags = args.t,
        output_pup_flag = args.pup,
        output_vt_tags = args.vtt
    )

    # Process each input file
    for ifile in ifile_l:
        labeler.process_file(ifile)

    # If ground truth, print precision, recall, and F1-measure
    if args.gt:
        precision, recall, fmeasure = labeler.compute_accuracy()
        log.info(
            "Precision: %.2f\tRecall: %.2f\tF1-Measure: %.2f\n" % \
                          (precision, recall, fmeasure))

    # Select output prefix
    out_prefix = os.path.basename(os.path.splitext(ifile_l[0])[0])

    # Output stats
    if args.stats:
        stats_filepath = "%s.stats" % out_prefix
        labeler.output_stats(stats_filepath)
        log.info('[-] Stats in %s' % (stats_filepath))

    # Output vendor info
    if args.avtags:
        vendor_filepath = "%s.avtags" % out_prefix
        labeler.output_vendor_info(vendor_filepath)
        log.info('[-] Vendor info in %s' % (vendor_filepath))

    # If alias detection, print map
    if args.aliasdetect:
        alias_filepath = "%s.alias" % out_prefix
        labeler.output_relations(alias_filepath)
        log.info('[-] Alias data in %s' % (alias_filepath))

    # Close output file
    if args.o:
        out_fd.close()

def parse_args():
    argparser = argparse.ArgumentParser(prog='avclass')

    argparser.add_argument('-f',
        action='append',
        help = 'Input JSONL file with AV labels.')

    argparser.add_argument('-d',
        action='append',
        help = 'Input directory. Process all files in this directory.')

    argparser.add_argument('-t',
        action='store_true',
        help='Output all tags, not only the family.')

    argparser.add_argument('-o',
        help='Output results to this file instead of stdout.')

    argparser.add_argument('-gt',
        help='file with ground truth. '
             'If provided it evaluates clustering accuracy. '
             'Prints precision, recall, F1-measure.')

    argparser.add_argument('-pup',
        action='store_true',
        help='if used each sample is classified as PUP or not')

    argparser.add_argument('-tag',
        default = DEFAULT_TAG_PATH,
        help='file with tagging rules.')

    argparser.add_argument('-tax',
        default = DEFAULT_TAX_PATH,
        help='file with taxonomy.')

    argparser.add_argument('-exp',
        default = DEFAULT_EXP_PATH,
        help='file with expansion rules.')

    argparser.add_argument('-aliasdetect',
        action='store_true',
        help='if used produce aliases file at end')

    argparser.add_argument('-av',
        help='file with list of AVs to use')

    argparser.add_argument('-avtags',
        action='store_true',
        help='extracts tags per av vendor')

    argparser.add_argument('-hash',
        choices=['md5', 'sha1', 'sha256'],
        help='hash used to name samples. Should match ground truth')

    argparser.add_argument('-vtt',
        action='store_true',
        help='Include VT tags in the output.')

    argparser.add_argument('-stats',
        action='store_true',
        help='if used produce 1 file with stats per category '
              '(File, Class, Behavior, Family, Unclassified)')

    args = argparser.parse_args()

    if (not args.f) and (not args.d):
        log.warning('No input files to process. Use -f or -d options')
        sys.exit(1)

    if args.tag:
        if args.tag == '/dev/null':
            log.info('[-] Using no tagging rules')
        else:
            log.info('[-] Using tagging rules in %s' % args.tag)
    else:
        log.info('[-] Using default tagging rules in %s' % DEFAULT_TAG_PATH)

    if args.tax:
        if args.tax == '/dev/null':
            log.info('[-] Using no taxonomy')
        else:
            log.info('[-] Using taxonomy in %s' % args.tax)
    else:
        log.info('[-] Using default taxonomy in %s' % DEFAULT_TAX_PATH)

    if args.exp:
        if args.exp == '/dev/null':
            log.info('[-] Using no expansion tags')
        else:
            log.info('[-] Using expansion tags in %s' % args.exp)
    else:
        log.info('[-] Using default expansion tags in %s' % DEFAULT_EXP_PATH)

    if args.av:
        log.info("[-] Using AV engines in %s" % args.av)

    # Build list of input files
    files = set(args.f) if args.f is not None else set()
    if args.d:
        for d in args.d:
            if os.path.isdir:
                for f in os.listdir(d):
                    filepath = os.path.join(d, f)
                    if os.path.isfile(filepath):
                        files.add(filepath)
            else:
                log.warning('Not a valid directory: %s' % d)
                sys.exit(1)
    ifile_l = sorted(files)

    # Check we have some file to process
    if (not ifile_l):
        log.warning('No input files to process.')
        sys.exit(1)

    return args, ifile_l

if __name__ == "__main__":
    main()
