#!/usr/bin/env python2
'''
AVClass labeler
'''

import sys
sys.path.insert(0, 'lib/')
import argparse
from avclass_common import AvLabels
from operator import itemgetter
import evaluate_clustering as ec
import json
import traceback
import os

def guess_hash(h):
    '''Given a hash string, guess the hash type based on the string length'''
    hlen = len(h)
    if hlen == 32:
        return 'md5'
    elif hlen == 40:
        return 'sha1'
    elif hlen == 64:
        return 'sha256'
    else:
        return None

def main(args):
    # Select hash used to identify sample, by default MD5
    hash_type = args.hash if args.hash else 'md5'

    # If ground truth provided, read it from file
    gt_dict = {}
    if args.gt:
        with open(args.gt, 'r') as gt_fd:
            for line in gt_fd:
                gt_hash, family = map(str.lower, line.strip().split('\t', 1))
                gt_dict[gt_hash] = family

        # Guess type of hash in ground truth file
        hash_type = guess_hash(gt_dict.keys()[0])

    # Create AvLabels object
    av_labels = AvLabels(args.gen, args.alias, args.av)

    # Select input file with AV labels
    ifile = args.vt if args.vt else args.lb

    # If verbose, open log file
    if args.verbose:
        log_filename = os.path.basename(os.path.splitext(ifile)[0]) + \
                            '.verbose'
        verb_fd = open(log_filename, 'w+')

    # Process each line in VirusTotal reports file
    vt_all = 0
    vt_empty = 0
    singletons = 0
    with open(ifile, 'r') as fd:
        first_token_dict = {}
        token_count_map = {}
        pair_count_map = {}
        token_family_map = {}

        for line in fd:

            # If blank line, skip
            if line == '\n':
                continue

            # Debug info
            if vt_all % 100 == 0:
                sys.stderr.write('\r%d VT reports read' % vt_all)
                sys.stderr.flush()
            vt_all += 1

            # Read JSON line and extract sample info (i.e., hashes and labels)
            vt_rep = json.loads(line)
            sample_info = av_labels.get_sample_info(vt_rep, args.vt)
            name = getattr(sample_info, hash_type)

            # If the VT report has no AV labels, continue
            if not sample_info[3]:
                vt_empty += 1
                sys.stderr.write('\nNo AV labels for %s\n' % name)
                sys.stderr.flush()
                continue
            
            # Get the distinct tokens from all the av labels in the report
            # And print them. If not verbose, print the first token.
            # If verbose, print the whole list
            try:
                # Get distinct tokens from AV labels
                tokens = av_labels.get_family_ranking(sample_info).items()

                # If alias detection, populate maps
                if args.aliasdetect:
                    prev_tok = ""
                    for entry in tokens:
                        curr_tok = entry[0]
                        curr_count = token_count_map.get(curr_tok)
                        if curr_count:
                            token_count_map[curr_tok] = curr_count + 1
                        else:
                            token_count_map[curr_tok] = 1
                        if prev_tok != "":
                            if prev_tok < curr_tok:
                                pair = (prev_tok,curr_tok) 
                            else: 
                                pair = (curr_tok,prev_tok)
                            pair_count = pair_count_map.get(pair)
                            if pair_count:
                                pair_count_map[pair] = pair_count + 1
                            else:
                                pair_count_map[pair] = 1
                        prev_tok = curr_tok

                # If generic token detection, populate map
                if args.gendetect and args.gt:
                    for entry in tokens:
                        curr_tok = entry[0]
                        curr_fam_set = token_family_map.get(curr_tok)
                        if curr_fam_set:
                            curr_fam_set.add(gt_dict[name])
                        else:
                            token_family_map[curr_tok] = \
                                set([gt_dict[name]])

                # Top candidate is most likely family name
                if tokens:
                    family = tokens[0][0]
                else:
                    family = "SINGLETON:" + name
                    singletons += 1

                # Check if sample is PUP, if requested
                if args.pup:
                    if av_labels.is_pup(sample_info[3]):
                        is_pup_str = "\t1"
                    else:
                        is_pup_str = "\t0"
                else:
                    is_pup_str =  ""

                # Build family map for precision, recall, computation
                first_token_dict[name] = family

                # Get ground truth family, if available
                gt_family = '\t' + gt_dict[name] if args.gt else ""

                # Print family (and ground truth if available) to stdout
                print '%s\t%s%s%s' % (name, family, gt_family, is_pup_str)

                # If verbose, print tokens (and ground truth if available) 
                # to log file
                if args.verbose:
                    verb_fd.write('%s\t%s%s%s\n' % (
                        name, tokens, gt_family, is_pup_str))

            except:
                traceback.print_exc(file=sys.stderr)
                continue

        # Debug info
        sys.stderr.write('\r%d VT reports read' % vt_all)
        sys.stderr.flush()
        sys.stderr.write('\n')

    # Print statistics
    sys.stderr.write(
            "Samples: %d NoLabels: %d Singletons: %d GroundTruth: %d\n" % (
            vt_all, vt_empty, singletons, len(gt_dict)))

    # If ground truth, print precision, recall, and f-measure
    if args.gt and args.eval:
        precision, recall, fmeasure = \
                    ec.eval_precision_recall_fmeasure(gt_dict,
                                                      first_token_dict)
        sys.stderr.write( \
            "Precision: %.2f\tRecall: %.2f\tF-Measure: %.2f\n" % \
                          (precision, recall, fmeasure))

    # If generic token detection, print map
    if args.gendetect:
        # Open generic tokens file
        gen_filename = os.path.basename(os.path.splitext(ifile)[0]) + \
                            '.gen'
        gen_fd = open(gen_filename, 'w+')
        # Output header line
        gen_fd.write("Token\t# Families\n")
        sorted_pairs = sorted(token_family_map.iteritems(), 
                              key=lambda x: len(x[1]) if x[1] else 0, 
                              reverse=True)
        for (t,fset) in sorted_pairs:
            gen_fd.write("%s\t%d\n" % (t, len(fset)))

        # Close generic tokens file
        gen_fd.close()

    # If alias detection, print map
    if args.aliasdetect:
        # Open alias file
        alias_filename = os.path.basename(os.path.splitext(ifile)[0]) + \
                            '.alias'
        alias_fd = open(alias_filename, 'w+')
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(
                pair_count_map.items(), key=itemgetter(1))
        # Output header line
        alias_fd.write("# t1\tt2\t|t1|\t|t2|\t|t1^t2|\t|t1^t2|/|t_1|\n")
        # Compute token pair statistic and output to alias file
        for (t1,t2),c in sorted_pairs:
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
            alias_fd.write("%s\t%s\t%d\t%d\t%d\t%0.2f\n" % (
                x,y,xn,yn,c,f))
        # Close alias file
        alias_fd.close()

    # Close log file
    if args.verbose:
        verb_fd.close()



if __name__=='__main__':
    argparser = argparse.ArgumentParser(prog='avclass_labeler',
        description='''Extracts the family of a set of samples.
            Also calculates precision and recall if ground truth available''')

    argparser.add_argument('-vt',
        help='file to parse with full VT reports '
             '(REQUIRED if -lb argument not present)')

    argparser.add_argument('-lb',
        help='file to parse with subset of VT reports'
             '{md5,sha1,sha256,scan_date,av_labels} '
             '(REQUIRED if -vt not present)')

    argparser.add_argument('-gt',
        help='file with ground truth')

    argparser.add_argument('-eval',
        action='store_true',
        help='if used it evaluates clustering accuracy.'
             ' Prints precision, recall, f-measure. Requires -gt parameter')

    argparser.add_argument('-alias',
        help='file with aliases. Default: manual.aliases',
        default = 'data/default.aliases')

    argparser.add_argument('-gen',
        help='file with generic tokens. Default: manual.generics',
        default = 'data/default.generics')

    argparser.add_argument('-av',
        help='file with list of AVs to use')

    argparser.add_argument('-pup',
        action='store_true',
        help='if used each sample is classified as PUP or not')

    argparser.add_argument('-gendetect',
        action='store_true',
        help='if used produce generics file at end. Requires -gt parameter')

    argparser.add_argument('-aliasdetect',
        action='store_true',
        help='if used produce aliases file at end')

    argparser.add_argument('-v', '--verbose',
        help='output .verbose file with distinct tokens',
        action='store_true')

    argparser.add_argument('-hash',
        help='hash used to name samples. Should match ground truth',
        choices=['md5', 'sha1', 'sha256'])

    args = argparser.parse_args()

    if not args.vt and not args.lb:
        sys.stderr.write('Argument -vt or -lb is required\n')
        exit(1)

    if args.vt and args.lb:
        sys.stderr.write('Use either -vt or -lb argument, not both.\n')
        exit(1)

    if args.gendetect and not args.gt:
        sys.stderr.write('Generic token detection requires -gt param\n')
        exit(1)

    if args.eval and not args.gt:
        sys.stderr.write('Evaluating clustering accuracy needs -gt param\n')
        exit(1)

    if args.alias and args.alias == '/dev/null':
        sys.stderr.write('[-] Using no aliases\n')

    if args.gen and args.gen == '/dev/null':
        sys.stderr.write('[-] Using no generic tokens\n')
        
    main(args)
