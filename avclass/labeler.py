#!/usr/bin/env python3

import argparse
import gzip
import json
import os
import sys
import traceback

from operator import itemgetter

try:
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import AvLabels, Taxonomy
    from avclass import evaluate as ec
except ModuleNotFoundError:
    # Helps find the avclasses when run from console
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
    from avclass.common import AvLabels, Taxonomy
    from avclass import evaluate as ec

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

def format_tag_pairs(l, taxonomy=None):
    """Return ranked tags as string"""
    if not l:
        return ""
    if taxonomy is not None:
        p = taxonomy.get_path(l[0][0])
    else:
        p = l[0][0]
    out = "%s|%d" % (p, l[0][1])
    for (t,s) in l[1:]:
        if taxonomy is not None:
            p = taxonomy.get_path(t) 
        else:
            p = t
        out += ",%s|%d" % (p, s)
    return out

def list_str(l, sep=", ", prefix=""):
    """Return list as a string"""
    if not l:
        return ""
    out = prefix + l[0]
    for s in l[1:]:
        out = out + sep + s
    return out

def open_file(filepath, av_labels):
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
    sample_info = av_labels.get_sample_info_vt_v3(report)
    if sample_info is not None:
        itype = "vt3"
        get_sample_info_fun = av_labels.get_sample_info_vt_v3
    else:
        sample_info = av_labels.get_sample_info_vt_v2(report)
        if sample_info is not None:
            itype = "vt2"
            get_sample_info_fun = av_labels.get_sample_info_vt_v2
        else:
            itype = "lb" 
            get_sample_info_fun = av_labels.get_sample_info_lb
    # Set file pointer to beginning again
    fd.seek(0, 0)
    # Return file descriptor and type
    return fd, itype, get_sample_info_fun

def main():
    # Parse arguments
    args, ifile_l = parse_args()

    # Select hash used to identify sample, by default MD5
    hash_type = args.hash if args.hash else 'md5'

    # If ground truth provided, read it from file
    gt_dict = {}
    if args.gt:
        with open(args.gt, 'r') as gt_fd:
            for line in gt_fd:
                gt_hash, family = map(str, line.strip().split('\t', 1))
                gt_dict[gt_hash] = family

        # Guess type of hash in ground truth file
        hash_type = guess_hash(list(gt_dict.keys())[0])

    # Create AvLabels object
    av_labels = AvLabels(args.tag, args.exp, args.tax,
                         args.av, args.aliasdetect)

    # Select output prefix
    out_prefix = os.path.basename(os.path.splitext(ifile_l[0])[0])

    # Initialize state
    first_token_dict = {}
    token_count_map = {}
    pair_count_map = {}
    vt_all = 0
    avtags_dict = {}
    stats = {'samples': 0, 'noscans': 0, 'tagged': 0, 'maltagged': 0,
             'FAM': 0, 'CLASS': 0, 'BEH': 0, 'FILE': 0, 'UNK': 0}

    # Process each input file
    for ifile in ifile_l:
        # Open file
        fd, itype, get_sample_info = open_file(ifile, av_labels)

        # Debug info, file processed
        sys.stderr.write('[-] Processing input file %s (%s)\n' % (ifile, itype))

        # Process all lines in file
        for line in fd:

            # If blank line, skip
            if line == '\n':
                continue

            # Debug info
            if vt_all % 100 == 0:
                sys.stderr.write('\r[-] %d JSON read' % vt_all)
                sys.stderr.flush()
            vt_all += 1

            # Read JSON line
            vt_rep = json.loads(line)

            # Extract sample info
            sample_info = get_sample_info(vt_rep)

            # If no sample info, log error and continue
            if sample_info is None:
                try:
                    name = vt_rep['md5']
                    sys.stderr.write('\nNo scans for %s\n' % name)
                except KeyError:
                    sys.stderr.write('\nCould not process: %s\n' % line)
                sys.stderr.flush()
                stats['noscans'] += 1
                continue

            # Sample's name is selected hash type (md5 by default)
            name = getattr(sample_info, hash_type)

            # If the VT report has no AV labels, output and continue
            if not sample_info.labels:
                sys.stdout.write('%s\t-\t[]\n' % (name))
                # sys.stderr.write('\nNo AV labels for %s\n' % name)
                # sys.stderr.flush()
                continue

            # Compute VT_Count (using list of AV engines if provided)
            vt_count = av_labels.get_sample_vt_count(sample_info)

            # Get the distinct tokens from all the av labels in the report
            # And print them. 
            try:
                av_tmp = av_labels.get_sample_tags(sample_info)
                tags = av_labels.rank_tags(av_tmp)

                # AV VENDORS PER TOKEN
                if args.avtags:
                    for t in av_tmp:
                        tmap = avtags_dict.get(t, {})
                        for av in av_tmp[t]:
                            ctr = tmap.get(av, 0)
                            tmap[av] = ctr + 1
                        avtags_dict[t] = tmap

                if args.aliasdetect:
                    prev_tokens = set()
                    for entry in tags:
                        curr_tok = entry[0]
                        curr_count = token_count_map.get(curr_tok, 0)
                        token_count_map[curr_tok] = curr_count + 1
                        for prev_tok in prev_tokens:
                            if prev_tok < curr_tok:
                                pair = (prev_tok,curr_tok)
                            else:
                                pair = (curr_tok,prev_tok)
                            pair_count = pair_count_map.get(pair, 0)
                            pair_count_map[pair] = pair_count + 1
                        prev_tokens.add(curr_tok)

                # Collect stats
                # FIX: should iterate once over tags, 
                # for both stats and aliasdetect
                if tags:
                    stats["tagged"] += 1
                    if args.stats:
                        if (vt_count > 3):
                            stats["maltagged"] += 1
                            cat_map = {'FAM': False, 'CLASS': False,
                                       'BEH': False, 'FILE': False, 'UNK':
                                           False}
                            for t in tags:
                                path, cat = av_labels.taxonomy.get_info(t[0])
                                cat_map[cat] = True
                            for c in cat_map:
                                if cat_map[c]:
                                    stats[c] += 1

                # Check if sample is PUP, if requested
                if args.pup:
                    if av_labels.is_pup(tags, av_labels.taxonomy):
                        is_pup_str = "\t1"
                    else:
                        is_pup_str = "\t0"
                else:
                    is_pup_str =  ""

                # Select family for sample
                fam = "SINGLETON:" + name
                for (t,s) in tags:
                    cat = av_labels.taxonomy.get_category(t)
                    if (cat == "UNK") or (cat == "FAM"):
                        fam = t
                        break

                # Get ground truth family, if available
                if args.gt:
                    first_token_dict[name] = fam
                    gt_family = '\t' + gt_dict.get(name, "")
                else:
                    gt_family = ""

                # Get VT tags as string
                if args.vtt:
                    vtt = list_str(sample_info.vt_tags, prefix="\t")
                else:
                    vtt = ""

                # Print family (and ground truth if available) or tags
                if args.t:
                    tag_str = format_tag_pairs(tags, av_labels.taxonomy)
                    sys.stdout.write('%s\t%d\t%s%s%s%s\n' %
                                     (name, vt_count, tag_str, gt_family,
                                      is_pup_str, vtt))
                else:
                    sys.stdout.write('%s\t%s%s%s\n' %
                                     (name, fam, gt_family, is_pup_str))
            except:
                traceback.print_exc(file=sys.stderr)
                continue

        # Debug info
        sys.stderr.write('\r[-] %d JSON read' % vt_all)
        sys.stderr.flush()
        sys.stderr.write('\n')

        # Close file
        fd.close()

    # Print statistics
    sys.stderr.write(
            "[-] Samples: %d NoScans: %d NoTags: %d GroundTruth: %d\n" % (
                vt_all, stats['noscans'], vt_all - stats['tagged'], 
                len(gt_dict)))

    # If ground truth, print precision, recall, and F1-measure
    if args.gt:
        precision, recall, fmeasure = \
                    ec.eval_precision_recall_fmeasure(gt_dict,
                                                      first_token_dict)
        sys.stderr.write(
            "Precision: %.2f\tRecall: %.2f\tF1-Measure: %.2f\n" % \
                          (precision, recall, fmeasure))

    # Output stats
    if args.stats:
        stats_fd = open("%s.stats" % out_prefix, 'w')
        num_samples = vt_all
        stats_fd.write('Samples: %d\n' % num_samples)
        num_tagged = stats['tagged']
        frac = float(num_tagged) / float(num_samples) * 100
        stats_fd.write('Tagged (all): %d (%.01f%%)\n' % (num_tagged, frac))
        num_maltagged = stats['maltagged']
        frac = float(num_maltagged) / float(num_samples) * 100
        stats_fd.write('Tagged (VT>3): %d (%.01f%%)\n' % (num_maltagged, frac))
        for c in ['FILE','CLASS','BEH','FAM','UNK']:
            count = stats[c]
            frac = float(count) / float(num_maltagged) * 100
            stats_fd.write('%s: %d (%.01f%%)\n' % (c, stats[c], frac))
        stats_fd.close()

    # Output vendor info
    if args.avtags:
        avtags_fd = open("%s.avtags" % out_prefix, 'w')
        for t in sorted(avtags_dict.keys()):
            avtags_fd.write('%s\t' % t)
            pairs = sorted(avtags_dict[t].items(),
                            key=lambda pair : pair[1],
                            reverse=True)
            for pair in pairs:
                avtags_fd.write('%s|%d,' % (pair[0], pair[1]))
            avtags_fd.write('\n')
        avtags_fd.close()

    # If alias detection, print map
    if args.aliasdetect:
        # Open alias file
        alias_filename = out_prefix + '.alias'
        alias_fd = open(alias_filename, 'w+')
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(
            pair_count_map.items(), key=itemgetter(1))
        # sorted_pairs = sorted(
        #     pair_count_map.items())

        # Output header line
        alias_fd.write("# t1\tt2\t|t1|\t|t2|\t"
                       "|t1^t2|\t|t1^t2|/|t1|\t|t1^t2|/|t2|\n")
        # Compute token pair statistic and output to alias file
        for (t1, t2), c in sorted_pairs:
            n1 = token_count_map[t1]
            n2 = token_count_map[t2]
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
            x = av_labels.taxonomy.get_path(x)
            y = av_labels.taxonomy.get_path(y)
            alias_fd.write("%s\t%s\t%d\t%d\t%d\t%0.2f\t%0.2f\n" % (
                x, y, xn, yn, c, f, finv))
        # Close alias file
        alias_fd.close()
        sys.stderr.write('[-] Alias data in %s\n' % (alias_filename))


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
        sys.stderr.write('No input files to process. Use -f or -d options\n')
        sys.exit(1)

    if args.tag:
        if args.tag == '/dev/null':
            sys.stderr.write('[-] Using no tagging rules\n')
        else:
            sys.stderr.write('[-] Using tagging rules in %s\n' % (
                              args.tag))
    else:
        sys.stderr.write('[-] Using default tagging rules in %s\n' % (
                          DEFAULT_TAG_PATH))

    if args.tax:
        if args.tax == '/dev/null':
            sys.stderr.write('[-] Using no taxonomy\n')
        else:
            sys.stderr.write('[-] Using taxonomy in %s\n' % (
                              args.tax))
    else:
        sys.stderr.write('[-] Using default taxonomy in %s\n' % (
                          DEFAULT_TAX_PATH))

    if args.exp:
        if args.exp == '/dev/null':
            sys.stderr.write('[-] Using no expansion tags\n')
        else:
            sys.stderr.write('[-] Using expansion tags in %s\n' % (
                              args.exp))
    else:
        sys.stderr.write('[-] Using default expansion tags in %s\n' % (
                          DEFAULT_EXP_PATH))

    # Build list of input files
    files = set(args.f) if args.f is not None else {}
    if args.d:
        for d in args.d:
            if os.path.isdir:
                for f in os.listdir(d):
                    filepath = os.path.join(d, f)
                    if os.path.isfile(filepath):
                        files.add(filepath)
            else:
                sys.stderr.write('Not a valid directory: %s\n' % d)
                sys.exit(1)
    ifile_l = sorted(files)

    # Check we have some file to process
    if (not ifile_l):
        sys.stderr.write('No input files to process.\n')
        sys.exit(1)

    return args, ifile_l

if __name__ == "__main__":
    main()
