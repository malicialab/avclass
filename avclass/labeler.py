import argparse
import gzip
import os
import json
import sys
import traceback


from io import StringIO
from operator import itemgetter
from pathlib import Path
from typing import AnyStr, Dict, List, NamedTuple, Optional, Tuple, Union

try:
    from avclass.common import AvLabels, Taxonomy
    from avclass import clustering as ec, util
except ModuleNotFoundError:
    # Helps find the avclasses when run from console
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from avclass.common import AvLabels, Taxonomy
    from avclass import clustering as ec, util


class AVClassLabeler:
    def __init__(self, av_labels: AvLabels = AvLabels()):
        self.av_labels = av_labels
        self.output = {"labels": []}
        self.hash_type = None
        self.ground_truth = None
        self.get_sample_info = None
        self.console = False
        self.av_tags = False
        self.stats_export = False
        self.family_only = False
        self.pup_classify = False
        self.path_export = False
        self.vt_tags = False
        self.vt_all = 0
        self.first_token_dict = {}
        self.token_count_map = {}
        self.pair_count_map = {}
        self.avtags_dict = {}
        self.gt_dict = {}
        self.stats = {
            "samples": 0,
            "noscans": 0,
            "tagged": 0,
            "maltagged": 0,
            "FAM": 0,
            "CLASS": 0,
            "BEH": 0,
            "FILE": 0,
            "UNK": 0,
        }

    def run(
        self,
        files: Union[
            AnyStr,
            List[AnyStr],
            Path,
            List[Path],
            StringIO,
            List[StringIO],
            Dict,
            List[Dict],
        ],
        data_type: Optional[AnyStr] = "vt3",
        hash_type: Optional[AnyStr] = "md5",
        ground_truth: Optional[AnyStr] = None,
        stats_export: bool = False,
        vt_tags: bool = False,
        av_tags: bool = False,
        pup_classify: bool = False,
        path_export: bool = False,
        family_only: bool = False,
        console: bool = False,
    ) -> List[Dict]:
        # Set class arguments
        self.console = console
        self.ground_truth = ground_truth
        self.av_tags = av_tags
        self.stats_export = stats_export
        self.family_only = family_only
        self.pup_classify = pup_classify
        self.path_export = path_export
        self.vt_tags = vt_tags

        # Select hash used to identify sample, by default MD5
        self.hash_type = self.get_hash_type(hash_type)

        # Select file type used for sampling
        data_type = data_type if data_type else "vt3"
        self.get_sample_info = self.av_labels.get_sample_call(data_type)

        # Select output prefix
        if isinstance(files, list) and isinstance(files[0], str):
            out_prefix = os.path.basename(os.path.splitext(files[0])[0])
        else:
            out_prefix = None

        # Process each input file
        if not isinstance(files, list):
            files = [files]
        for ifile in files:
            # Open file
            if isinstance(ifile, dict):
                self.process_line(ifile)
                continue
            elif isinstance(ifile, StringIO):
                fd = ifile
            else:
                if self.is_gz_file(ifile):
                    fd = gzip.open(ifile, "rt")
                else:
                    fd = open(ifile, "r")

                # Debug info, file processed
                self.print_error("[-] Processing input file %s\n" % ifile)

            # Process all lines in file
            try:
                for line in fd:
                    self.process_line(line)
            except json.decoder.JSONDecodeError:
                if isinstance(ifile, str):
                    self.print_error(
                        "Error parsing %s (possible incorrect file type\n" % ifile
                    )
                continue

            # Debug info
            self.print_error("\r[-] %d JSON read" % self.vt_all, flush=True)
            self.print_error("\n")

            # Close file
            fd.close()

        # Print statistics
        self.print_statistics()

        # If ground truth, print precision, recall, and F1-measure
        if self.ground_truth:
            self.ground_truth_print()

        # Output stats
        if self.stats_export:
            self.out_stats(out_prefix)

        # Output av vendor info
        if self.av_tags:
            self.out_avtags(out_prefix)

        # If alias detection, print map
        if self.av_labels.alias_detect:
            self.alias_detection(out_prefix, path_export)

        return self.output

    def process_line(self, line: Union[AnyStr, Dict]):
        if isinstance(line, str):
            # If blank line, skip
            if line == "\n":
                return

            # Debug info
            if self.vt_all % 100 == 0:
                self.print_error("\r[-] %d JSON read\n" % self.vt_all, flush=True)
            self.vt_all += 1

            # Read JSON line
            vt_rep = json.loads(line)
        else:
            vt_rep = line

        # Extract sample info
        sample_info = self.get_sample_info(vt_rep)

        # If no sample info, log error and continue
        if sample_info is None:
            try:
                name = vt_rep["md5"]
                self.print_error("\nNo scans for %s\n" % name, flush=True)
            except KeyError:
                self.print_error("\nCould not process: %s\n" % line, flush=True)
            self.stats["noscans"] += 1
            return

        # Get the distinct tokens from all the av labels in the report
        # And print them.
        try:
            self.get_tokens(sample_info)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return

    def get_tokens(self, sample_info: NamedTuple):
        # Sample's name is selected hash type (md5 by default)
        name = getattr(sample_info, self.hash_type)

        # If the VT report has no AV labels, output and continue
        if not sample_info.labels:
            self.print_output("%s\t-\t[]\n" % (name))
            # self.print_error('\nNo AV labels for %s\n' % name, flush=True)
            return

        # AV VENDORS PER TOKEN
        av_tmp = self.av_labels.get_sample_tags(sample_info)
        if self.av_tags:
            self.av_vender_tags(av_tmp)

        tags = self.av_labels.rank_tags(av_tmp)
        if self.av_labels.alias_detect:
            self.av_vender_tokens(tags)

        # Compute VT_Count
        vt_count = len(sample_info.labels)

        # Collect stats
        # TODO: should iterate once over tags,
        # for both stats and aliasdetect
        if tags:
            self.collect_stats(tags, vt_count)

        # Select family for sample if needed,
        # i.e., for compatibility mode or for ground truth
        fam, gt_family = self.get_family(name, tags)

        # Check if sample is PUP, if requested
        pup_val = self.is_pup(self.pup_classify, tags)

        # Print family (and ground truth if available)
        if self.family_only:
            class_entry = self.avclass1_output(
                name=name,
                family=fam,
                ground_truth=gt_family,
                pup_val=pup_val,
                vt_count=vt_count,
            )
            self.output["labels"].append(class_entry)
        else:
            class_entry = self.avclass2_output(
                name=name,
                tags=tags,
                sample_info=sample_info,
                ground_truth=gt_family,
                pup_val=pup_val,
                vt_count=vt_count,
            )
            self.output["labels"].append(class_entry)

    def avclass1_output(
        self,
        name: AnyStr,
        family: AnyStr,
        ground_truth: AnyStr,
        pup_val: Optional[bool],
        vt_count: int,
    ) -> Dict:
        """
        Build the v1 classification entry

        :param name: Hash
        :param family: family classification
        :param ground_truth:
        :param pup_val: is a pup
        :param vt_count:
        :return: Dict of classification
        """
        self.print_output(
            "%s\t%s%s%s\n" % (name, family, ground_truth, self.get_pup_str(pup_val))
        )
        # Build json output
        values = {"hash": name, "av_count": vt_count, "family": family}
        if self.ground_truth:
            values["ground_truth"] = ground_truth
        if self.pup_classify:
            values["pup"] = pup_val
        return values

    def avclass2_output(
        self,
        name: AnyStr,
        ground_truth: AnyStr,
        pup_val: Optional[bool],
        vt_count: int,
        tags: List[Tuple],
        sample_info: NamedTuple,
    ) -> Dict:
        """
        Build the v2 classification entry

        :param name: Hash
        :param ground_truth:
        :param pup_val: is a pup
        :param vt_count:
        :param tags: List of tags and their count
        :param sample_info:
        :return: Dict of classification
        """
        # Build string output
        if self.vt_tags:
            vtt = self.list_str(sample_info.vt_tags, prefix="\t")
        else:
            vtt = ""
        tag_str = self.format_tag_pairs_str(
            tags=tags, taxonomy=self.av_labels.taxonomy, path_export=self.path_export
        )
        self.print_output(
            "%s\t%d\t%s%s%s%s\n"
            % (name, vt_count, tag_str, ground_truth, self.get_pup_str(pup_val), vtt)
        )
        # Build json output
        tag_dict = self.format_tag_pairs_list(
            tags=tags, taxonomy=self.av_labels.taxonomy, path_export=self.path_export
        )
        values = {"hash": name, "av_count": vt_count, "tags": tag_dict}
        if self.ground_truth:
            values["ground_truth"] = self.gt_dict.get(name, "")
        if self.pup_classify:
            values["pup"] = pup_val
        if self.vt_tags:
            values["vt_tags"] = sample_info.vt_tags
        return values

    def get_family(self, name: AnyStr, tags: List[Tuple]) -> Tuple:
        if self.family_only or self.ground_truth:
            fam = "SINGLETON:" + name
            # fam = ''
            for (t, s) in tags:
                cat = self.av_labels.taxonomy.get_category(t)
                if (cat == "UNK") or (cat == "FAM"):
                    fam = t
                    break
        else:
            fam = ""

        # Get ground truth family, if available
        if self.ground_truth:
            self.first_token_dict[name] = fam
            gt_family = "\t" + self.gt_dict.get(name, "")
        else:
            gt_family = ""
        return (fam, gt_family)

    def collect_stats(self, tags: List[Tuple], vt_count: int):
        self.stats["tagged"] += 1
        if self.stats_export and vt_count > 3:
            self.stats["maltagged"] += 1
            cat_map = {
                "FAM": False,
                "CLASS": False,
                "BEH": False,
                "FILE": False,
                "UNK": False,
            }
            for t in tags:
                cat = self.av_labels.taxonomy.get_info(t[0])[1]
                cat_map[cat] = True
            for c in cat_map:
                if cat_map[c]:
                    self.stats[c] += 1

    def av_vender_tags(self, av_tmp: Dict):
        for t in av_tmp:
            tmap = self.avtags_dict.get(t, {})
            for av in av_tmp[t]:
                ctr = tmap.get(av, 0)
                tmap[av] = ctr + 1
            self.avtags_dict[t] = tmap

    def av_vender_tokens(self, tags: List[Tuple]):
        prev_tokens = set()
        for entry in tags:
            curr_tok = entry[0]
            curr_count = self.token_count_map.get(curr_tok, 0)
            self.token_count_map[curr_tok] = curr_count + 1
            for prev_tok in prev_tokens:
                if prev_tok < curr_tok:
                    pair = (prev_tok, curr_tok)
                else:
                    pair = (curr_tok, prev_tok)
                pair_count = self.pair_count_map.get(pair, 0)
                self.pair_count_map[pair] = pair_count + 1
            prev_tokens.add(curr_tok)

    def get_pup_str(self, is_pup: Optional[bool] = None) -> AnyStr:
        if is_pup is True:
            return "\t1"
        elif is_pup is False:
            return "\t0"
        else:
            return ""

    def is_pup(self, pup_classify: bool, tags: List[Tuple]) -> Optional[bool]:
        if pup_classify:
            if self.av_labels.is_pup(tags, self.av_labels.taxonomy):
                is_pup = True
            else:
                is_pup = False
        else:
            is_pup = None
        return is_pup

    def get_hash_type(self, hash_type: Optional[AnyStr] = None) -> AnyStr:
        if self.ground_truth:
            with open(self.ground_truth, "r") as gt_fd:
                for line in gt_fd:
                    gt_hash, family = map(str, line.strip().split("\t", 1))
                    self.gt_dict[gt_hash] = family
            # Guess type of hash in ground truth file
            return self.guess_hash(list(self.gt_dict.keys())[0])
        else:
            return hash_type if hash_type else "md5"

    def print_statistics(self):
        self.print_error(
            "[-] Samples: %d NoScans: %d NoTags: %d GroundTruth: %d\n"
            % (
                self.vt_all,
                self.stats["noscans"],
                self.vt_all - self.stats["tagged"],
                len(self.gt_dict),
            )
        )

    def ground_truth_print(self):
        # If ground truth, print precision, recall, and F1-measure
        precision, recall, fmeasure = ec.eval_precision_recall_fmeasure(
            self.gt_dict, self.first_token_dict
        )
        self.print_error(
            "Precision: %.2f\tRecall: %.2f\tF1-Measure: %.2f\n"
            % (precision, recall, fmeasure)
        )
        self.output["ground_truth"] = {
            "precision": "%.2f" % precision,
            "recall": "%.2f" % recall,
            "f1-measure": "%.2f" % fmeasure,
        }

    def alias_detection(self, out_prefix: AnyStr, path_export: bool = False):
        self.output["alias"] = []
        alias_fd = None
        alias_filename = None
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(self.pair_count_map.items(), key=itemgetter(1))
        # sorted_pairs = sorted(self.pair_count_map.items())

        # Open alias file
        if out_prefix:
            alias_filename = out_prefix + ".alias"
            alias_fd = open(alias_filename, "w+")
            # Output header line
            alias_fd.write(
                "# t1\tt2\t|t1|\t|t2|\t|t1^t2|\t|t1^t2|/|t1|\t|t1^t2|/|t2|\n"
            )
        # Compute token pair statistic and output to alias file
        for (t1, t2), c in sorted_pairs:
            n1 = self.token_count_map[t1]
            n2 = self.token_count_map[t2]
            if n1 < n2:
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
            if path_export:
                x = self.av_labels.taxonomy.get_path(x)
                y = self.av_labels.taxonomy.get_path(y)
            self.output["alias"].append(
                {
                    "alias_token": x,
                    "alias_tag": y,
                    "count_token": xn,
                    "count_tag": yn,
                    "ratio": c,
                    "ratio_token": f,
                    "raiio_tag": finv,
                }
            )
            if out_prefix:
                alias_fd.write(
                    "%s\t%s\t%d\t%d\t%d\t%0.2f\t%0.2f\n" % (x, y, xn, yn, c, f, finv)
                )
        if out_prefix:
            # Close alias file
            alias_fd.close()
            self.print_error("[-] Alias data in %s\n" % (alias_filename))

    def out_avtags(self, out_prefix: AnyStr):
        if out_prefix:
            avtags_fd = open("%s.avtags" % out_prefix, "w")
            for t in sorted(self.avtags_dict.keys()):
                avtags_fd.write("%s\t" % t)
                pairs = sorted(
                    self.avtags_dict[t].items(), key=lambda pair: pair[1], reverse=True
                )
                for pair in pairs:
                    avtags_fd.write("%s|%d," % (pair[0], pair[1]))
                avtags_fd.write("\n")
            avtags_fd.close()
        self.output["av_tags"] = {}
        for tag in sorted(self.avtags_dict.keys()):
            self.output["av_tags"][tag] = []
            pairs = sorted(
                self.avtags_dict[tag].items(), key=lambda pair: pair[1], reverse=True
            )
            for pair in pairs:
                self.output["av_tags"][tag].append({"name": pair[0], "count": pair[1]})

    def out_stats(self, out_prefix: AnyStr):
        # Output stats
        num_samples = self.vt_all
        num_tagged = self.stats["tagged"]
        tag_frac = float(num_tagged) / float(num_samples) * 100

        num_maltagged = self.stats["maltagged"]
        maltag_frac = float(num_maltagged) / float(num_samples) * 100
        if out_prefix:
            stats_fd = open("%s.stats" % out_prefix, "w")
            stats_fd.write("Samples: %d\n" % num_samples)
            stats_fd.write("Tagged (all): %d (%.01f%%)\n" % (num_tagged, tag_frac))
            stats_fd.write(
                "Tagged (VT>3): %d (%.01f%%)\n" % (num_maltagged, maltag_frac)
            )
            for c in ["FILE", "CLASS", "BEH", "FAM", "UNK"]:
                count = self.stats[c]
                frac = float(count) / float(num_maltagged) * 100
                stats_fd.write("%s: %d (%.01f%%)\n" % (c, self.stats[c], frac))
            stats_fd.close()
        self.output["stats"] = {
            "samples": num_samples,
            "tagged_all": {"count": num_tagged, "ratio": "%.01f%%" % tag_frac},
            "tagged_vt3": {"count": num_maltagged, "ratio": "%.01f%%" % maltag_frac},
            "category": [],
        }
        for cat in ["FILE", "CLASS", "BEH", "FAM", "UNK"]:
            count = self.stats[cat]
            frac = float(count) / float(num_maltagged) * 100
            self.output["stats"]["category"].append(
                {cat: {"count": count, "ratio": "%.01f%%" % frac}}
            )

    def guess_hash(self, h: AnyStr) -> Optional[AnyStr]:
        """
        Guess hash type based on ``len(h)``

        :param h: The hash
        :return: The hash type (str)
        """
        hlen = len(h)
        if hlen == 32:
            return "md5"
        elif hlen == 40:
            return "sha1"
        elif hlen == 64:
            return "sha256"
        return None

    def format_tag_pairs_str(
        self, tags: List[Tuple], taxonomy: Taxonomy = None, path_export: bool = False
    ) -> AnyStr:
        """
        Get ranked tags as a string.

        :param tags:
        :param taxonomy:
        :return: List of tags
        """
        if not tags:
            return ""
        if path_export and taxonomy is not None:
            p = taxonomy.get_path(tags[0][0])
        else:
            p = tags[0][0]
        out = "%s|%d" % (p, tags[0][1])
        for (t, s) in tags[1:]:
            if path_export and taxonomy is not None:
                p = taxonomy.get_path(t)
            else:
                p = t
            out += ",%s|%d" % (p, s)
        return out

    def format_tag_pairs_list(
        self, tags: List[Tuple], taxonomy: Taxonomy = None, path_export: bool = False
    ) -> List[Dict]:
        """
        Get ranked tags as a list dictionary.

        :param tags:
        :param taxonomy:
        :return: List of tags
        """
        out = []
        for (tag, count) in tags:
            values = {"tag": tag, "count": count}
            if path_export and taxonomy is not None:
                values["category"] = taxonomy.get_category(tag)
                values["path"] = taxonomy.get_path(tag)
            out.append(values)
        return out

    def list_str(
        self, vt_tags: Optional[Dict], sep: AnyStr = ", ", prefix: AnyStr = ""
    ) -> AnyStr:
        """
        Return list as a string

        :param vt_tags: The list of virus total tags
        :param sep: The separator
        :param prefix: The prefix
        :return: A string representation of the list
        """
        if not vt_tags or len(vt_tags) == 0:
            return ""
        out = prefix + vt_tags[0]
        for s in vt_tags[1:]:
            out = out + sep + s
        return out

    def is_gz_file(self, filepath):
        with open(filepath, "rb") as test_f:
            return test_f.read(2) == b"\x1f\x8b"

    def print_error(self, output: AnyStr = "", flush=False):
        if self.console:
            # TODO - would this be better? print(output, file=sys.stderr, flush=flush, end="")
            sys.stderr.write(output)
            if flush:
                sys.stderr.flush()

    def print_output(self, output: AnyStr = ""):
        if self.console:
            sys.stdout.write(output)


def main():
    args = parse_args()
    # Create AvLabels object
    av_labels = AvLabels(
        tag_file=args.tag,
        tax_file=args.tax,
        exp_file=args.exp,
        av_file=args.av,
        alias_detect=args.aliasdetect,
    )
    # Build list of input files
    files = get_arg_files(
        file_input=args.input,
    )
    av_class = AVClassLabeler(av_labels=av_labels)
    result = av_class.run(
        files=files,
        data_type=args.type,
        hash_type=args.hash,
        stats_export=args.stats,
        vt_tags=args.vtt,
        av_tags=args.avtags,
        ground_truth=args.gt,
        pup_classify=args.pup,
        path_export=args.path,
        family_only=args.c,
        console=not args.json,
    )
    if args.json:
        print(json.dumps(result))


def get_arg_files(
    file_input: List[AnyStr],
) -> List[AnyStr]:
    """
    Return List of the files to process

    :param file_input: file(s) or directory to process
    :return: List of type str
    """
    ifile_l = []
    for fi in file_input:
        if os.path.isdir(fi):
            for f in os.listdir(fi):
                dir_file = os.path.join(fi, f)
                if dir_file not in ifile_l:
                    ifile_l.append(dir_file)
        elif fi not in ifile_l:
            ifile_l.append(fi)
    return ifile_l


def parse_args():
    argparser = argparse.ArgumentParser(
        prog="avclass",
        description="Extracts tags for a set of samples.  Also calculates precision and"
        " recall if ground truth available",
    )

    argparser.add_argument(
        "-i",
        "--input",
        action="append",
        help="input report file (plain or gzip) or directory. (Can be provided multiple times)",
    )

    argparser.add_argument(
        "-t", "--type", help="the type of report file (vt2, vt3, lb, md)"
    )

    argparser.add_argument(
        "-gt",
        help="file with ground truth. If provided it evaluates clustering accuracy. "
        "Prints precision, recall, F1-measure.",
    )

    argparser.add_argument(
        "-vtt", help="Include VT tags in the output.", action="store_true"
    )

    argparser.add_argument(
        "-tag", help="file with tagging rules.", default=util.DEFAULT_TAG_PATH
    )

    argparser.add_argument(
        "-tax", help="file with taxonomy.", default=util.DEFAULT_TAX_PATH
    )

    argparser.add_argument(
        "-exp", help="file with expansion rules.", default=util.DEFAULT_EXP_PATH
    )

    argparser.add_argument("-av", help="file with list of AVs to use")

    argparser.add_argument(
        "-avtags", help="extracts tags per av vendor", action="store_true"
    )

    argparser.add_argument(
        "-pup",
        action="store_true",
        help="if used each sample is classified as PUP or not",
    )

    argparser.add_argument(
        "-p", "--path", help="output.full path for tags", action="store_true"
    )

    argparser.add_argument(
        "-hash",
        help="hash used to name samples. Should match ground truth",
        choices=["md5", "sha1", "sha256"],
    )

    argparser.add_argument(
        "-c",
        help="Compatibility mode. Outputs results in AVClass format.",
        action="store_true",
    )

    argparser.add_argument(
        "-aliasdetect", action="store_true", help="if used produce aliases file at end"
    )

    argparser.add_argument(
        "-json", "--json", action="store_true", help="output console to json"
    )

    argparser.add_argument(
        "-stats",
        action="store_true",
        help="if used produce 1 file with stats per category "
        "(File, Class, Behavior, Family, Unclassified)",
    )

    args = argparser.parse_args()

    if not args.input:
        sys.stderr.write("Input file / directory is required: " "-i\n")
        exit(1)

    if not args.type:
        sys.stderr.write(
            "[-] No type defined, using file type of VirusTotal v3: '-t vt3'\n"
        )

    devnull = "/dev/null"
    # TODO - consider letting argparse handle this?
    if args.tag:
        if args.tag == devnull:
            sys.stderr.write("[-] Using no tagging rules\n")
        else:
            sys.stderr.write("[-] Using tagging rules in %s\n" % args.tag)
    else:
        sys.stderr.write(
            "[-] Using default tagging rules in %s\n" % util.DEFAULT_TAG_PATH
        )

    # TODO - consider letting argparse handle this?
    if args.tax:
        if args.tax == devnull:
            sys.stderr.write("[-] Using no taxonomy\n")
        else:
            sys.stderr.write("[-] Using taxonomy in %s\n" % args.tax)
    else:
        sys.stderr.write("[-] Using default taxonomy in %s\n" % util.DEFAULT_TAX_PATH)

    # TODO - consider letting argparse handle this?
    if args.exp:
        if args.exp == devnull:
            sys.stderr.write("[-] Using no expansion tags\n")
        else:
            sys.stderr.write("[-] Using expansion tags in %s\n" % args.exp)
    else:
        sys.stderr.write(
            "[-] Using default expansion tags in %s\n" % util.DEFAULT_EXP_PATH
        )

    return args


if __name__ == "__main__":
    main()
