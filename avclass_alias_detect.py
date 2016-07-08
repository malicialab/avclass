#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
AVClass Alias detect
'''
import sys
import argparse
import subprocess
import os


def main(args):
    itype = '-vt' if args.vt else '-lb'
    ifile = args.vt if args.vt else args.lb
    FNULL = open(os.devnull, 'w')
    sys.stderr.write('[-] Running avclass_labeler on given dataset.\n')
    labeler = subprocess.Popen(\
       "python avclass_labeler.py %s %s -alias /dev/null -aliasdetect" % 
       (itype, ifile), shell=True, stdout=FNULL)
    labeler.wait()
    alias_fname = os.path.basename(os.path.splitext(ifile)[0]) + '.alias'
    sys.stderr.write('[-] Processing token pairs.\n')
    with open(alias_fname, 'r') as fr:
        for pos, line in enumerate(fr):
            cline = line.strip('\n')
            # Print headers
            if not pos:
                print cline
                continue
            t1, t2, t1_num, t2_num, nalias_num, talias_num = cline.split('\t')
            if int(nalias_num) > args.nalias and\
              float(talias_num) > args.talias:
                print cline
    sys.stderr.write('[-] Done.\n')


if __name__=='__main__':
    argparser = argparse.ArgumentParser(prog='avclass_alias_detect',
        description='''Given a collection of VT reports it detects aliases
        used by AVs. It runs the avclass_labeler with specific arguments
        and processes the output.''')

    argparser.add_argument('-vt',
        help='file to parse with full VT reports '
             '(REQUIRED if -lb argument not present)')

    argparser.add_argument('-lb',
        help='file to parse with subset of VT reports'
             '{md5,sha1,sha256,scan_date,av_labels} '
             '(REQUIRED if -vt not present)')

    argparser.add_argument('-gen',
        help='file with generic tokens. Default: manual.generics',
        default = 'manual.generics')

    argparser.add_argument('-nalias',
        help='Minimum number of times that a pair of tokes have been seen.'
             'Default: 20',
        type=int,
        default = 20)

    argparser.add_argument('-talias',
        help='Minimum percentage of times two tokens appear together.'
             'Default: 0.94',
        type=float,
        default = 0.94)

    args = argparser.parse_args()

    if not args.vt and not args.lb:
        sys.stderr.write('Argument -vt or -lb is required\n')
        exit(1)

    if args.vt and args.lb:
        sys.stderr.write('Use either -vt or -lb argument, not both.\n')
        exit(1)

    main(args)

