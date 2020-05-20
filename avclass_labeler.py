#!/usr/bin/env python2
'''
AVClass labeler
'''

import os
import sys
path = os.path.dirname(os.path.abspath(__file__))
libpath = os.path.join(path, 'lib/')
sys.path.insert(0, libpath)
import argparse
from avclass_common import AvLabels
from operator import itemgetter
import evaluate_clustering as ec
import json
import traceback

# Default alias file
default_alias_file = os.path.join(path, "data/default.aliases")
# Default generic tokens file
default_gen_file = os.path.join(path, "data/default.generics")

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
        hash_type = guess_hash(list(gt_dict.keys())[0])

    # Create AvLabels object
    av_labels = AvLabels(args.gen, args.alias, args.av)

    # Build list of input files
    # NOTE: duplicate input files are not removed
    ifile_l = []
    if (args.vt):
        ifile_l += args.vt
        ifile_are_vt = True
    if (args.lb):
        ifile_l += args.lb
        ifile_are_vt = False
    if (args.vtdir): 
        ifile_l += [os.path.join(args.vtdir, f) for f in os.listdir(args.vtdir)]
        ifile_are_vt = True
    if (args.lbdir):
        ifile_l += [os.path.join(args.lbdir, f) for f in os.listdir(args.lbdir)]
        ifile_are_vt = False

    # Select correct sample info extraction function
    if not ifile_are_vt:
        get_sample_info = av_labels.get_sample_info_lb
    elif args.vt3:
        get_sample_info = av_labels.get_sample_info_vt_v3
    else:
        get_sample_info = av_labels.get_sample_info_vt_v2

    # Select output prefix
    out_prefix = os.path.basename(os.path.splitext(ifile_l[0])[0])

    # If verbose, open log file
    if args.verbose:
        log_filename = out_prefix + '.verbose'
        verb_fd = open(log_filename, 'w+')

    # Initialize state
    first_token_dict = {}
    token_count_map = {}
    pair_count_map = {}
    token_family_map = {}
    fam_stats = {}
    vt_all = 0
    vt_empty = 0
    singletons = 0

    # Process each input file
    for ifile in ifile_l:
        # Open file
        fd = open(ifile, 'r')

        # Debug info, file processed
        sys.stderr.write('[-] Processing input file %s\n' % ifile)

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

            # Read JSON line and extract sample info (i.e., hashes and labels)
            vt_rep = json.loads(line)
            sample_info = get_sample_info(vt_rep)
            if sample_info is None:
                try:
                    name = vt_rep['md5']
                    sys.stderr.write('\nNo AV labels for %s\n' % name)
                except KeyError:
                    sys.stderr.write('\nCould not process: %s\n' % line)
                sys.stderr.flush()
                vt_empty += 1
                continue

            # Sample's name is selected hash type (md5 by default)
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
                tokens = list(av_labels.get_family_ranking(sample_info).items())

                # If alias detection, populate maps
                if args.aliasdetect:
                    prev_tokens = set()
                    for entry in tokens:
                        curr_tok = entry[0]
                        curr_count = token_count_map.get(curr_tok)
                        if curr_count:
                            token_count_map[curr_tok] = curr_count + 1
                        else:
                            token_count_map[curr_tok] = 1
                        for prev_tok in prev_tokens:
                            if prev_tok < curr_tok:
                                pair = (prev_tok,curr_tok) 
                            else: 
                                pair = (curr_tok,prev_tok)
                            pair_count = pair_count_map.get(pair)
                            if pair_count:
                                pair_count_map[pair] = pair_count + 1
                            else:
                                pair_count_map[pair] = 1
                        prev_tokens.add(curr_tok)

                # If generic token detection, populate map
                if args.gendetect and args.gt:
                    for entry in tokens:
                        curr_tok = entry[0]
                        curr_fam_set = token_family_map.get(curr_tok)
                        family = gt_dict[name] if name in gt_dict else None
                        if curr_fam_set and family:
                            curr_fam_set.add(family)
                        elif family:
                            token_family_map[curr_tok] = set(family)

                # Top candidate is most likely family name
                if tokens:
                    family = tokens[0][0]
                    is_singleton = False
                else:
                    family = "SINGLETON:" + name
                    is_singleton = True
                    singletons += 1

                # Check if sample is PUP, if requested
                if args.pup:
                    is_pup = av_labels.is_pup(sample_info[3])
                    if is_pup:
                        is_pup_str = "\t1"
                    else:
                        is_pup_str = "\t0"
                else:
                    is_pup = None
                    is_pup_str =  ""

                # Build family map for precision, recall, computation
                first_token_dict[name] = family

                # Get ground truth family, if available
                if args.gt:
                    gt_family = '\t' + gt_dict[name] if name in gt_dict else ""
                else:
                    gt_family = ""

                # Print family (and ground truth if available) to stdout
                sys.stdout.write('%s\t%s%s%s\n' % (name, family, gt_family, 
                                                    is_pup_str))

                # If verbose, print tokens (and ground truth if available) 
                # to log file
                if args.verbose:
                    verb_fd.write('%s\t%s%s%s\n' % (
                        name, tokens, gt_family, is_pup_str))

                # Store family stats (if required)
                if args.fam:
                    if is_singleton:
                        ff = 'SINGLETONS'
                    else:
                        ff = family
                    try:
                        numAll, numMal, numPup = fam_stats[ff]
                    except KeyError:
                        numAll = 0
                        numMal = 0
                        numPup = 0

                    numAll += 1
                    if args.pup:
                        if is_pup:
                            numPup += 1
                        else:
                            numMal += 1
                    fam_stats[ff] = (numAll, numMal, numPup)

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
            "[-] Samples: %d NoLabels: %d Singletons: %d "
            "GroundTruth: %d\n" % (
                vt_all, vt_empty, singletons, len(gt_dict)))

    # If ground truth, print precision, recall, and F1-measure
    if args.gt and args.eval:
        precision, recall, fmeasure = \
                    ec.eval_precision_recall_fmeasure(gt_dict,
                                                      first_token_dict)
        sys.stderr.write( \
            "Precision: %.2f\tRecall: %.2f\tF1-Measure: %.2f\n" % \
                          (precision, recall, fmeasure))

    # If generic token detection, print map
    if args.gendetect:
        # Open generic tokens file
        gen_filename = out_prefix + '.gen'
        gen_fd = open(gen_filename, 'w+')
        # Output header line
        gen_fd.write("Token\t#Families\n")
        sorted_pairs = sorted(token_family_map.items(), 
                              key=lambda x: len(x[1]) if x[1] else 0, 
                              reverse=True)
        for (t,fset) in sorted_pairs:
            gen_fd.write("%s\t%d\n" % (t, len(fset)))

        # Close generic tokens file
        gen_fd.close()
        sys.stderr.write('[-] Generic token data in %s\n' % (gen_filename))

    # If alias detection, print map
    if args.aliasdetect:
        # Open alias file
        alias_filename = out_prefix + '.alias'
        alias_fd = open(alias_filename, 'w+')
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(
                pair_count_map.items(), key=itemgetter(1))
        # Output header line
        alias_fd.write("# t1\tt2\t|t1|\t|t2|\t|t1^t2|\t|t1^t2|/|t1|\n")
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
        sys.stderr.write('[-] Alias data in %s\n' % (alias_filename))

    # If family statistics, output to file
    if args.fam:
        # Open family file
        fam_filename = out_prefix + '.families'
        fam_fd = open(fam_filename, 'w+')
        # Output header line
        if args.pup:
            fam_fd.write("# Family\tTotal\tMalware\tPUP\tFamType\n")
        else:
            fam_fd.write("# Family\tTotal\n")
        # Sort map
        sorted_pairs = sorted(fam_stats.items(), key=itemgetter(1),
                              reverse=True)
        # Print map contents
        for (f,fstat) in sorted_pairs:
            if args.pup:
                if fstat[1] > fstat[2]:
                    famType = "malware"
                else:
                    famType = "pup"
                fam_fd.write("%s\t%d\t%d\t%d\t%s\n" % (f, fstat[0], fstat[1],
                                                fstat[2], famType))
            else:
                fam_fd.write("%s\t%d\n" % (f, fstat[0]))
        # Close file
        fam_fd.close()
        sys.stderr.write('[-] Family data in %s\n' % (fam_filename))

    # Close log file
    if args.verbose:
        sys.stderr.write('[-] Verbose output in %s\n' % (log_filename))
        verb_fd.close()



if __name__=='__main__':
    argparser = argparse.ArgumentParser(prog='avclass_labeler',
        description='''Extracts the family of a set of samples.
            Also calculates precision and recall if ground truth available''')

    argparser.add_argument('-vt', action='append',
        help='file with VT reports '
             '(Can be provided multiple times)')

    argparser.add_argument('-lb', action='append',
        help='file with simplified JSON reports '
             '{md5,sha1,sha256,scan_date,av_labels} '
             '(Can be provided multiple times)')

    argparser.add_argument('-vtdir',
        help='existing directory with VT reports')

    argparser.add_argument('-lbdir',
        help='existing directory with simplified JSON reports')

    argparser.add_argument('-gt',
        help='file with ground truth')

    argparser.add_argument('-eval',
        action='store_true',
        help='if used it evaluates clustering accuracy.'
             ' Prints precision, recall, F1-measure. Requires -gt parameter')

    argparser.add_argument('-alias',
        help='file with aliases.',
        default = default_alias_file)

    argparser.add_argument('-gen',
        help='file with generic tokens.',
        default = default_gen_file)

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
        action='store_true',
        help='output .verbose file with distinct tokens')

    argparser.add_argument('-hash',
        help='hash used to name samples. Should match ground truth',
        choices=['md5', 'sha1', 'sha256'])

    argparser.add_argument('-fam',
        action='store_true',
        help='if used produce families file with PUP/malware counts per family')

    argparser.add_argument('-vt3', action='store_true',
        help='input are VT v3 files')

    args = argparser.parse_args()

    if not args.vt and not args.lb and not args.vtdir and not args.lbdir:
        sys.stderr.write('One of the following 4 arguments is required: '
                          '-vt,-lb,-vtdir,-lbdir\n')
        exit(1)

    if (args.vt or args.vtdir) and (args.lb or args.lbdir):
        sys.stderr.write('Use either -vt/-vtdir or -lb/-lbdir. '
                          'Both types of input files cannot be combined.\n')
        exit(1)

    if args.gendetect and not args.gt:
        sys.stderr.write('Generic token detection requires -gt param\n')
        exit(1)

    if args.eval and not args.gt:
        sys.stderr.write('Evaluating clustering accuracy needs -gt param\n')
        exit(1)

    if args.alias:
        if args.alias == '/dev/null':
            sys.stderr.write('[-] Using no aliases\n')
            args.alias = None
        else:
            sys.stderr.write('[-] Using aliases in %s\n' % (
                              args.alias))
    else:
        sys.stderr.write('[-] Using generic aliases in %s\n' % (
                          default_alias_file))

    if args.gen:
        if args.gen == '/dev/null':
            sys.stderr.write('[-] Using no generic tokens\n')
            args.gen = None
        else:
            sys.stderr.write('[-] Using generic tokens in %s\n' % (
                              args.gen))
    else:
        sys.stderr.write('[-] Using default generic tokens in %s\n' % (
                          default_gen_file))
        
    main(args)
