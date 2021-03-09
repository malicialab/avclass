import logging
import operator
import re
import string
import sys

from avclass import util
from collections import defaultdict, namedtuple
from typing import AnyStr, Callable, Collection, Dict, List, Optional, Set, Tuple, Union


logger = logging.getLogger(__name__)

# Prefix to identify platform tags
platform_prefix = "FILE:os:"

# Default category for tags in taxonomy with no category
uncategorized_cat = "UNC"

SampleInfo = namedtuple("SampleInfo", ["md5", "sha1", "sha256", "labels", "vt_tags"])

# AVs to use in suffix removal
suffix_removal_av_set = {
    "Norman",
    "Avast",
    "Avira",
    "Kaspersky",
    "ESET-NOD32",
    "Fortinet",
    "Jiangmin",
    "Comodo",
    "GData",
    "Avast",
    "Sophos",
    "BitDefenderTheta",
    "Alibaba",
    "Tencent",
    "Cyren",
    "Arcabit",
    "TrendMicro-HouseCall",
    "TrendMicro",
    "NANO-Antivirus",
    "Microsoft",
}


class Tag:
    """ A Tag in the taxonomy """

    def __init__(self, s):
        word_list = s.strip().split(":")
        if len(word_list) > 1:
            self._name = word_list[-1].lower()
            self._cat = word_list[0].upper()
            self._prefix_l = [x.lower() for x in word_list[1:-1]]
            path = self._cat
            for x in self._prefix_l:
                path = path + ":" + x
            self._path = path + ":" + self._name
        else:
            self._name = word_list[0].lower()
            self._cat = uncategorized_cat
            self._prefix_l = []
            self._path = self._name

    def __hash__(self):
        """ Return hash """
        return hash((self._path))

    @property
    def name(self):
        """ Return tag name """
        return self._name

    @property
    def cat(self):
        """ Return tag category """
        return self._cat

    @property
    def path(self):
        """ Return tag path """
        return self._path

    @property
    def prefix_l(self):
        """ Return tag prefix list """
        return self._prefix_l


class Taxonomy:
    """
    Contains tags and generic tokens read from filesystem
    """

    def __init__(self, filepath: Optional[AnyStr]):
        """
        Initialize and populate the Tag map from ``filepath``

        :param filepath: Path to taxonomy data
        """
        self._tags = set()
        self._tag_map = {}
        if filepath:
            self.read_taxonomy(filepath)

    def __len__(self) -> int:
        """
        The number of tags contained in __tag_map (divided by 2 because we store paths there too)

        :return: The length (int) of the Taxonomy
        """
        return len(self._tags)

    def __iter__(self):
        """ Iterator over the alphabetically sorted tags in the taxonomy """
        return (t for t in sorted(self._tags))

    def is_generic(self, tag: AnyStr) -> bool:
        """
        Whether or not the input ``tag`` is generic

        :param tag: The tag
        :return: Boolean
        """
        t = self._tag_map.get(tag, None)
        return getattr(t, "cat", None) == "GEN"

    def is_tag(self, tag: AnyStr) -> bool:
        """
        Whether this Taxonomy is aware of ``tag``

        :param tag: The tag
        :return: Boolean
        """
        return tag in self._tag_map

    def add_tag(self, s: AnyStr, override: bool = False):
        """
        Add a tag (``s``) to the Taxonomy.  Collisions are only replaced if ``override`` is truthy.

        :param s: A string to create a Tag from
        :param override: Whether or not to replace a duplicate if present
        :return: None
        """
        tag = Tag(s)
        t = self._tag_map.get(tag.name, None)

        if t and (t.path != tag.path):
            if override:
                logger.warning("[Taxonomy] Replacing %s with %s\n" % t.path, tag.path)
                del self._tag_map[t.path]
            else:
                return

        logger.debug("[Taxonomy] Adding tag %s" % s)
        self._tag_map[tag.name] = tag
        self._tag_map[tag.path] = tag

    def remove_tag(self, tag: AnyStr) -> bool:
        """
        Remove a Tag from the Taxonomy.

        :param tag: The tag to remove
        :return: Whether or not the tag was present
        """
        t = self._tag_map.get(tag, None)
        if tag:
            logger.debug("[Taxonomy] Removing tag: %s" % t.path)
            del self._tag_map[t.name]
            del self._tag_map[t.path]
            self._tags.remove(tag)
        return t is not None

    def get_category(self, tag: AnyStr) -> AnyStr:
        """
        Return the tag's category or "UNK" if it's not a tag.

        :param tag: The tag
        :return: The category
        """
        t = self._tag_map.get(tag, None)
        return getattr(t, "cat", "UNK")

    def get_path(self, tag: AnyStr) -> AnyStr:
        """
        Get a tag's full path.

        :param tag: The tag
        :return: The tag's path
        """
        t = self._tag_map.get(tag, None)
        return getattr(t, "path", f"UNK:{tag}")

    def get_prefix_l(self, tag: AnyStr) -> List[AnyStr]:
        """
        Get a tag's prefix list.

        :param tag: The tag
        :return: The tag's prefix list
        """
        t = self._tag_map.get(tag, None)
        return getattr(t, "prefix_l", [])

    def get_prefix(self, tag: AnyStr) -> List[AnyStr]:
        """
        Get a tag's prefixes.

        :param tag: The tag
        :return: String representation of the tag's full prefix
        """
        t = self._tag_map.get(tag, None)
        tag_pfx = tag.path.split(":")[:-1]
        return t.prefix_l if t else tag_pfx

    def get_depth(self, tag: AnyStr) -> int:
        """
        Determine the "depth" (token count) of the tag

        :param tag: The tag
        :return: The depth (int) of the tag
        """
        t = self._tag_map.get(tag, None)
        if t:
            return len(tag.prefix_l) + 2
        return 0

    def get_info(self, tag: AnyStr) -> Tuple[AnyStr, AnyStr]:
        """
        Get tag info (path, category) or "UNK:tag"

        :param tag: The tag
        :return: Tuple containing tag.path and tag.cat
        """
        t = self._tag_map.get(tag, None)
        if t:
            return t.path, t.cat
        return f"UNK:{tag}", "UNK"

    def expand(self, tag: AnyStr) -> List[AnyStr]:
        """
        Return tag prefixes that are leaf-nodes

        :param tag: The tag
        :return: A list of prefixes
        """
        t = self._tag_map.get(tag, None)
        if t:
            return [x for x in t.prefix_l if x in self._tag_map]
        return []

    def platform_tags(self) -> Set[AnyStr]:
        """
        Returns a set of platform tags in the Taxonomy

        :return: Set of platformn tags
        """
        return {
            tag.name
            for _, tag in self._tag_map.items()
            if tag.path.startswith(platform_prefix)
        }

    def overlaps(self, t1: AnyStr, t2: AnyStr) -> bool:
        """
        Whether or not the two tags overlap

        :param t1: The first Tag
        :param t2: The second Tag
        :return: Boolean
        """
        m1 = self.get_prefix_l(t1)
        m2 = self.get_prefix_l(t2)
        return t1 in m2 or t2 in m1

    def remove_overlaps(
        self, l: Collection[AnyStr]
    ) -> Union[Collection[AnyStr], List[AnyStr]]:
        """
        Returns list with overlapping tags removed

        :param l: The list
        :return: Deduped list
        """
        # TODO - code smell
        if not l:
            return l
        pair_l = sorted([(self.get_depth(t), t) for t in l])
        out_l = [pair_l.pop()[1]]
        while pair_l:
            t = pair_l.pop()[1]
            if not any(self.overlaps(t, e) for e in out_l):
                out_l.append(t)
        return out_l

    def read_taxonomy(self, filepath: AnyStr):
        """
        Create Taxonomy from file (tab-separated lines)

        :param filepath: The path of the file to read
        :return: None
        """
        with open(filepath, "r") as fd:
            for line in fd:
                line = line.strip()
                if not line.startswith("#") and line:
                    self.add_tag(line)

    def to_file(self, filepath: AnyStr):
        """
        Write sorted Taxonomy to a file (tab-separated lines)

        :param filepath: The path to write
        :return: None
        """
        with open(filepath, "w") as fd:
            tag_l = sorted(self._tag_map.items(), key=lambda item: item[1].path)
            idx = 0
            for name, tag in tag_l:
                if (idx % 2) == 0:
                    fd.write(tag.path + "\n")
                idx += 1


class Rules:
    """
    Map a single source with one or more destinations
    """

    def __init__(self, filepath: Optional[AnyStr]):
        """
        Initialize the rule-map and read rules from ``filepath``

        :param filepath: The file to read from
        """
        self._src_map = {}
        if filepath:
            self.read_rules(filepath)

    def __len__(self):
        """
        The number of rules/src in the rule-map

        :return: Number of rules
        """
        return len(self._src_map)

    def add_rule(
        self, src: AnyStr, dst_l: Collection[AnyStr] = None, overwrite: bool = False
    ):
        """
        Add a rule to the map.  On duplicate, append destinations.  If ``overwrite`` is set, replace rule src/dst.

        :param src: The source tag
        :param dst_l: The destination list
        :param overwrite: Whether or not to overwrite duplicates
        :return: None
        """
        # Remove src from dst_l if it exists
        dst_l = filter(lambda x: x != src, dst_l)
        if not dst_l:
            return

        logger.debug("[Rules] Adding %s -> %s" % (src, dst_l))
        src_tag = Tag(src)
        if overwrite:
            target_l = [Tag(dst).name for dst in dst_l]
            self._src_map[src_tag.name] = set(target_l)
        else:
            curr_dst = self._src_map.get(src_tag.name, set())
            for dst in dst_l:
                dst_tag = Tag(dst)
                curr_dst.add(dst_tag.name)
            self._src_map[src_tag.name] = curr_dst

    def remove_rule(self, src: AnyStr) -> bool:
        dst = self._src_map.get(src, [])
        if dst:
            logger.debug("[Rules] Removing rule: %s -> %s" % (src, dst))
            del self._src_map[src]
            return True
        return False

    def get_dst(self, src: AnyStr) -> List[AnyStr]:
        """
        Returns a the dst belonging to src or an empty list.

        :param src: The source rule
        :return: List of dst
        """
        return list(self._src_map.get(src, []))

    def read_rules(self, filepath: AnyStr):
        """
        Read rules from a file and create the rule-map.

        :param filepath: The path of the file to read
        :return: None
        """
        with open(filepath, "r") as fd:
            for line in fd:
                line = line.strip()
                if not line.startswith("#") and line:
                    word_list = line.split()
                    if len(word_list) > 1:
                        self.add_rule(word_list[0], word_list[1:])

    def to_file(self, filepath: AnyStr, taxonomy: Taxonomy = None):
        """
        Write current rules to the file at ``filepath``.

        :param filepath: The path of the file to write
        :param taxonomy: A Taxonomy to optionally resolve full tag paths
        :return: None
        """
        with open(filepath, "w") as fd:
            for src, dst_set in sorted(self._src_map.items()):
                dst_l = sorted(dst_set)
                if taxonomy:
                    src_path = taxonomy.get_path(src)
                    path_l = [taxonomy.get_path(t) for t in dst_l]
                    dst_str = "\t".join(path_l)
                    fd.write("%s\t%s\n" % (src_path, dst_str))
                else:
                    dst_str = "\t".join(dst_l)
                    fd.write("%s\t%s\n" % (src, dst_str))

    def expand_src_destinations(self, src: AnyStr) -> Set[AnyStr]:
        """
        Return a list of all expanded destinations for ``src``

        :param src: The source
        :return: List of expanded destinations
        """
        # TODO - this only goes one layer deep it seems.  Not actually recursive
        dst_set = self._src_map.get(src, set())
        out = set()
        while dst_set:
            dst = dst_set.pop()
            dst_l = self._src_map.get(dst, [])
            if dst_l:
                for d in dst_l:
                    if d not in out and d != dst:
                        dst_set.add(d)
            else:
                out.add(dst)
        return out

    def expand_all_destinations(self):
        """
        Expand/resolve all sources in the rule-map

        :return: None
        """
        src_l = self._src_map.keys()
        for src in src_l:
            dst_l = self.expand_src_destinations(src)
            self._src_map[src] = dst_l


class Translation(Rules):
    """
    Translations are a set of rules that convert between unknown labels and labels that are in our Taxonomy
    """

    def __init__(self, filepath: AnyStr):
        super().__init__(filepath)

    def validate(self, taxonomy: Taxonomy):
        """
        Ensure all "destination" labels are in the Taxonomy.

        :param taxonomy: The Taxonomy to use for checking
        :return: None
        """
        for tok, tag_l in self._src_map.items():
            if taxonomy.is_tag(tok):
                sys.stdout.write("[Tagging] SRC %s in taxonomy\n" % tok)
            for t in tag_l:
                if not taxonomy.is_tag(t):
                    sys.stdout.write("[Tagging] %s not in taxonomy\n" % t)
                    # TODO - raise or return False?


class Expansion(Rules):
    """
    Expansions are rules that allow us to map a single label (src) to all explicit and implicit labels
    """

    def __init__(self, filepath: AnyStr):
        super().__init__(filepath)

    def validate(self, taxonomy: Taxonomy):
        """
        Ensure all "source" and "destination" labels are in the Taxonomy.

        :param taxonomy: The Taxonomy to use for checking
        :return: None
        """
        for src, dst_set in self._src_map.items():
            if not taxonomy.is_tag(src):
                sys.stdout.write("[Expansion] %s not in taxonomy\n" % src)
                # TODO - raise or return False?
            for dst in dst_set:
                if not taxonomy.is_tag(dst):
                    sys.stdout.write("[Expansion] %s not in taxonomy\n" % dst)
                    # TODO - raise or return False?


class AvLabels:
    """
    Primary class used to interpret AV Labels
    """

    def __init__(
        self,
        tag_file: AnyStr = util.DEFAULT_TAG_PATH,
        exp_file: AnyStr = util.DEFAULT_EXP_PATH,
        tax_file: AnyStr = util.DEFAULT_TAX_PATH,
        av_file: AnyStr = None,
        alias_detect: bool = False,
    ):
        self.taxonomy = Taxonomy(tax_file)
        self.translations = Translation(tag_file)
        self.expansions = Expansion(exp_file)
        self.avs = self.read_avs(av_file) if av_file else None
        # Alias statistics initialization
        self.alias_detect = alias_detect

    def get_sample_call(self, data_type: AnyStr) -> Callable:
        """
        Return the correct parser for the report type

        :param data_type: the type of file vt2, vt3, lb, md
        :return: Callable function that returns SampleInfo
        """
        if data_type == "lb":
            return self.get_sample_info_lb
        elif data_type == "vt" or data_type == "vt2":
            return self.get_sample_info_vt_v2
        elif data_type == "vt3":
            return self.get_sample_info_vt_v3
        elif data_type == "md":
            return self.get_sample_info_md
        else:
            sys.stderr.write(
                "Invalid data type for sample: %s (should be vt, vt2, vt3, lb, md)"
                % data_type
            )
            return self.get_sample_info_vt_v3

    @staticmethod
    def read_avs(avs_file: AnyStr) -> Set[AnyStr]:
        """
        Read AV engines from ``avs_file``

        :param avs_file: The file to read
        :return: A set containing the engines
        """
        with open(avs_file) as fd:
            avs = set(map(str.strip, fd.readlines()))
        return avs

    @staticmethod
    def get_sample_info_lb(record: Dict) -> SampleInfo:
        """
        Convert simplified JSON to a SampleInfo object

        :param record: The JSON record
        :return: An instance of SampleInfo
        """
        return SampleInfo(
            record["md5"], record["sha1"], record["sha256"], record["av_labels"], []
        )

    @staticmethod
    def get_sample_info_vt_v2(record: Dict) -> SampleInfo:
        """
        Convert VirusTotal (v2) JSON to a SampleInfo object

        :param record: The JSON record
        :return: An instance of SampleInfo
        """
        try:
            scans = record["scans"]
            md5 = record["md5"]
            sha1 = record["sha1"]
            sha256 = record["sha256"]
        except KeyError:
            return None

        # Obtain labels from scan results
        label_pairs = []
        for av, res in scans.items():
            if res["detected"]:
                label = res["result"]
                clean_label = "".join(
                    filter(lambda x: x in string.printable, label)
                ).strip()
                label_pairs.append((av, clean_label))

        vt_tags = record.get("tags", [])

        return SampleInfo(md5, sha1, sha256, label_pairs, vt_tags)

    @staticmethod
    def get_sample_info_vt_v3(record: Dict) -> SampleInfo:
        """
        Convert VirusTotal (v3) JSON to a SampleInfo object

        :param record: The JSON record
        :return: An instance of SampleInfo
        """
        if "data" in record:
            record = record["data"]
        try:
            scans = record["attributes"]["last_analysis_results"]
            md5 = record["attributes"]["md5"]
            sha1 = record["attributes"]["sha1"]
            sha256 = record["attributes"]["sha256"]
        except KeyError:
            return None

        # Obtain labels from scan results
        label_pairs = []
        for av, res in scans.items():
            label = res["result"]
            if label is not None:
                clean_label = "".join(
                    filter(lambda x: x in string.printable, label)
                ).strip()
                label_pairs.append((av, clean_label))

        vt_tags = record["attributes"].get("tags", [])

        return SampleInfo(md5, sha1, sha256, label_pairs, vt_tags)

    @staticmethod
    def get_sample_info_md(record: Dict) -> SampleInfo:
        """
        Convert OPSWAT MetaDefender JSON to a SampleInfo object

        :param record: The JSON record
        :return: An instance of SampleInfo
        """
        try:
            scans = record["scan_results"]["scan_details"]
            md5 = record["file_info"]["md5"]
            sha1 = record["file_info"]["sha1"]
            sha256 = record["file_info"]["sha256"]
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

    @staticmethod
    def is_pup(tag_pairs: List[Tuple], taxonomy: Taxonomy) -> Optional[bool]:
        """
        Attempts to classify a sample (represented by ``tag_pairs``) as a PUP.  We accomplish this by checking for the
        "grayware" label in the highest ranked CLASS.

        :param tag_pairs: List of tuples containing a label, and rank (int)
        :param taxonomy: The Taxonomy
        :return: bool or None
        """
        threshold = 0.5
        if len(tag_pairs) < 1:
            return None

        max_ctr = tag_pairs[0][1]
        for tag, ctr in tag_pairs:
            path, cat = taxonomy.get_info(tag)
            if cat == "CLASS":
                if "grayware" in path:
                    return float(ctr) >= float(max_ctr) * threshold
                else:
                    return False
        return False

    @staticmethod
    def _remove_suffixes(av_name: AnyStr, label: AnyStr) -> AnyStr:
        """
        Remove vendor-specific suffixes from the label

        :param av_name: The AV name to remove
        :param label: The label to change
        :return: The new label
        """
        # Truncate after last '.'
        if av_name in suffix_removal_av_set:
            label = label.rsplit(".", 1)[0]

        # Truncate after last '.'
        # if suffix only contains digits or uppercase (no lowercase) chars
        if av_name == "AVG":
            tokens = label.rsplit(".", 1)
            if len(tokens) > 1 and re.match("^[A-Z0-9]+$", tokens[1]):
                label = tokens[0]

        # Truncate after last '!'
        if av_name == "Agnitum":
            label = label.rsplit("!", 1)[0]

        return label

    def get_label_tags(self, label: AnyStr, hashes: Collection[AnyStr]) -> Set[AnyStr]:
        """
        Tokenize, translate, and filter a label into tags.  ``hashes`` are used to provide a dynamic filter of sorts.
        We don't want to tokenize parts of the sample's hash which is a common thing for some AV vendors.

        :param label: The label to convert
        :param hashes: A list of hashes to be used as dynamic filters
        :return: A set of tags that were extracted from the label
        """
        tags = set()

        # If empty label, nothing to do
        if not label:
            return tags

        # Split label into tokens and process each token
        for token in re.split("[^0-9a-zA-Z]", label):
            # Convert token to lowercase
            token = token.lower()

            # Remove digits at the end
            end_len = len(re.findall("\d*$", token)[0])
            if end_len:
                token = token[:-end_len]

            # Ignore token if prefix of a hash of the sample
            # Most AVs use MD5 prefixes in labels,
            # but we check SHA1 and SHA256 as well
            if any([h.startswith(token) for h in hashes]):
                continue

            # Ignore generic tokens
            if self.taxonomy.is_generic(token):
                continue

            # Apply tagging rule
            dst_l = self.translations.get_dst(token)
            if dst_l:
                # Ignore generic tokens
                for t in dst_l:
                    if not self.taxonomy.is_generic(t):
                        tags.add(t)
            # Add token if longer than 3 characters and no tagging rule
            elif len(token) > 3:
                tags.add(token)

        # Return tags
        return tags

    def _expand(self, tag_set: Set[AnyStr]) -> Set[AnyStr]:
        """
        Expand tags into more tags using expansion rules and the Taxonomy

        :param tag_set: Starting set of tags
        :return: Expanded set of tags
        """
        ret = set()
        for t in tag_set:
            # Include tag
            ret.add(t)

            # Include target of expansion rule in output
            ret.update(self.expansions.get_dst(t))

            # Include implicit expansions in taxonomy
            ret.update(self.taxonomy.expand(t))

        return ret

    def get_sample_tags(self, sample_info: SampleInfo) -> Dict[AnyStr, List[AnyStr]]:
        """
        Get a dictionary where the key is a tag and the value is a list of AV engines that confirmed that tag.

        :param sample_info: The SampleInfo object to inspect
        :return: A dictionary where k,v = tag,[av, ...]
        """
        duplicates = set()
        av_dict = defaultdict(list)

        # Process each AV label
        for av_name, label in sample_info.labels:
            if not label or (self.avs and av_name not in self.avs):
                continue

            # Emsisoft uses same label as
            # GData/ESET-NOD32/BitDefender/Ad-Aware/MicroWorld-eScan,
            # but suffixes ' (B)' to their label. Remove the suffix.
            label = label.rstrip(" (B)")

            # F-Secure uses Avira's engine since Nov. 2018
            # but prefixes 'Malware.' to Avira's label. Remove the prefix.
            label = label.lstrip("Malware.")

            # Other engines often use exactly the same label, e.g.,
            #   AVG/Avast
            #   K7Antivirus/K7GW
            #   Kaspersky/ZoneAlarm

            if label in duplicates:
                continue

            duplicates.add(label)

            label = self._remove_suffixes(av_name, label)
            hashes = [sample_info.md5, sample_info.sha1, sample_info.sha256]
            tags = self.get_label_tags(label, hashes)

            # NOTE: Avoid expansion when aliases are set
            expanded_tags = tags if self.alias_detect else self._expand(tags)

            # store av vendors for each tag
            for t in expanded_tags:
                av_dict[t].append(av_name)

        return av_dict

    @staticmethod
    def rank_tags(
        av_dict: Dict[AnyStr, List[AnyStr]], threshold: int = 1
    ) -> List[Tuple[AnyStr, int]]:
        """
        Get a list of tuples containing a tag and the number of AV that confirmed that tag sorted by number of AV
        (descending).

        :param av_dict: The AV dictionary (from ``get_sample_tags()``)
        :param threshold: The minimum rank/count to include
        :return: A sorted list of tag, av-count pairs
        """
        pairs = ((t, len(avs)) for t, avs in av_dict.items() if len(avs) > threshold)
        return sorted(pairs, key=operator.itemgetter(1, 0), reverse=True)
