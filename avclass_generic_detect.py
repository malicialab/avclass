#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
AVClass Generic detect
'''
import sys
import argparse
import subprocess
import os


def main(args):
    # Set input switch
    itype = '-vt' if args.vt else '-lb'
    ifile = args.vt if args.vt else args.lb

    # Run avclass_labeler
    sys.stderr.write('[-] Running avclass_labeler on %s\n' % (ifile))
    FNULL = open(os.devnull, 'w')
    labeler = subprocess.Popen(\
       "python avclass_labeler.py %s %s -alias /dev/null"\
       " -gen /dev/null -gendetect -gt %s" % 
       (itype, ifile, args.gt), shell=True, stdout=FNULL)
    labeler.wait()

    # Process generic tokens file
    sys.stderr.write('[-] Processing results.\n')
    gen_fname = os.path.basename(os.path.splitext(ifile)[0]) + '.gen'
    with open(gen_fname, 'r') as fr:
        for pos, line in enumerate(fr):
            cline = line.strip('\n')
            # Print headers
            if not pos:
                print cline
                continue
            token, fam_num = cline.split('\t')
            if int(fam_num) > args.tgen:
                print cline

    # Done
    sys.stderr.write('[-] Done.\n')


if __name__=='__main__':
    argparser = argparse.ArgumentParser(prog='avclass_alias_detect',
        description='''Given a collection of VT reports and the family
        names of these samples (i.e., groundtruth) it generates a list
        of generic tokens to be excluded from labeling.''')

    argparser.add_argument('-vt',
        help='file to parse with full VT reports '
             '(REQUIRED if -lb argument not present)')

    argparser.add_argument('-lb',
        help='file to parse with subset of VT reports'
             '{md5,sha1,sha256,scan_date,av_labels} '
             '(REQUIRED if -vt not present)')

    argparser.add_argument('-tgen',
        help='Minimum number of families that a token appears. '
             'Default: 8',
        type=int,
        default = 8)

    argparser.add_argument('-gt',
        help='file with ground truth')

    args = argparser.parse_args()

    if not args.vt and not args.lb:
        sys.stderr.write('Argument -vt or -lb is required\n')
        exit(1)

    if args.vt and args.lb:
        sys.stderr.write('Use either -vt or -lb argument, not both.\n')
        exit(1)

    if not args.gt:
        sys.stderr.write('Generic token detection needs groundtruth (-gt)\n')
        exit(1)

    main(args)

