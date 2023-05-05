import logging
import re
import sys

from collections import OrderedDict as OrdDict
from collections import namedtuple
from operator import itemgetter, attrgetter
from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH

# Set logging
log = logging.getLogger(__name__)

# Prefix to identify platform tags
platform_prefix = "FILE:os:"

# Default category for tags in taxonomy with no category
uncategorized_cat  = "UNC"

SampleInfo = namedtuple('SampleInfo', 
                        ['md5', 'sha1', 'sha256', 'labels', 'vt_tags'])

# AVs to use in suffix removal
suffix_removal_av_set = {
    'Norman',
    'Avast',
    'Avira',
    'Kaspersky',
    'ESET-NOD32',
    'Fortinet',
    'Jiangmin',
    'Comodo',
    'GData',
    'Sophos',
    'TrendMicro-HouseCall',
    'TrendMicro',
    'NANO-Antivirus',
    'Microsoft'
}

class Tag:
    """A Tag in the taxonomy"""
    def __init__(self, s):
        word_list = s.strip().split(":")
        if len(word_list) > 1:
            self._name = word_list[-1].lower()
            self._cat = word_list[0].upper()
            self._prefix_l = [x.lower() for x in word_list[1:-1]]
            path = self._cat
            for x in self._prefix_l:
                path = path + ':' + x
            self._path = path + ':' + self._name
        else:
            self._name = word_list[0].lower()
            self._cat = uncategorized_cat
            self._prefix_l = []
            self._path = self._name

    def __hash__(self):
        """Return hash"""
        return hash((self._path))

    def __eq__(self, other):
        return self.name == other.name

    def __lt__(self, other):
        return self.name < other.name

    @property
    def name(self):
        """Return tag name"""
        return self._name

    @property
    def cat(self):
        """Return tag category"""
        return self._cat

    @property
    def path(self):
        """Return tag path"""
        return self._path

    @property
    def prefix_l(self):
        """Return tag prefix list"""
        return self._prefix_l


class Taxonomy:
    """A taxonomy of tags and generic tokens read from file"""
    def __init__(self, filepath):
        """Initialize and populate _tag_map from input file"""
        self._tags = set() # Map tag.name | tag.path -> Tag
        self._tag_map = {}
        if filepath:
            self.read_taxonomy(filepath)

    def __len__(self):
        """Taxonomy length is the number of tags it contains"""
        return len(self._tags)

    def __iter__(self):
        """Iterator over the alphabetically sorted tags in the taxonomy"""
        return (t for t in sorted(self._tags))

    def is_generic(self, t):
        """Whether the input tag is generic"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.cat == "GEN"
        else:
            return False

    def is_tag(self, t):
        """Whether the input tag exists in the taxonomy"""
        return t in self._tag_map

    def add_tag(self, s, override=False):
        """Add the input tag to the taxonomy 

        If tag already exists with different path, 
        it is only replaced if override is True
        """
        tag = Tag(s)
        t = self._tag_map.get(tag.name, None)
        if t and (t.path != tag.path):
            if (not override):
                return
            else:
                log.warning("[Taxonomy] Replacing %s with %s\n" % (
                                  t.path, tag.path))
                del self._tag_map[t.path]
        log.debug("[Taxonomy] Adding tag %s" % s)
        self._tags.add(tag)
        self._tag_map[tag.name] = tag
        self._tag_map[tag.path] = tag
        return

    def remove_tag(self, t):
        """Remove tag from taxonomy. Returns whether tag was removed"""
        tag = self._tag_map.get(t, None)
        if tag:
            log.debug("[Taxonomy] Removing tag: %s" % tag.path)
            del self._tag_map[tag.name]
            del self._tag_map[tag.path]
            self._tags.remove(tag)
        return tag is not None

    def get_category(self, t):
        """Return category of input tag, UNK if not a tag"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.cat
        else:
            return "UNK"

    def get_path(self, t):
        """Return full path for given tag, or empty string if not a tag"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.path
        else:
            return ("UNK:" + t)

    def get_prefix_l(self, t):
        """Return prefix list for given tag, or empty string if not a tag"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.prefix_l
        else:
            return []

    def get_prefix(self, t):
        """Return prefix string for given tag, or empty string if not a tag"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.prefix_l
        else:
            return t.path[0:t.path.rfind(':')]

    def get_depth(self, t):
        """Return depth of tag in taxonomy. 

        Returns zero if tag not in taxonomy. 
        A normal tag CAT:name has depth two
        """
        tag = self._tag_map.get(t, None)
        if tag:
            return len(tag.prefix_l) + 2
        else:
            return 0

    def get_info(self, t):
        """Return (path,category) for given tag, or UNK:t if not a tag"""
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.path, tag.cat
        else:
            return "UNK:" + t, "UNK"

    def expand(self, t):
        """Return list of tags in prefix list that are leaves"""
        tag = self._tag_map.get(t, None)
        if tag:
            return [t for t in tag.prefix_l if t in self._tag_map]
        else:
            return []

    def platform_tags(self): 
        """Returns list with platform tags in taxonomy"""
        acc = set()
        for idx,tag in self._tag_map.items():
            if tag.path.startswith(platform_prefix):
                acc.add(tag.name)
        return acc

    def overlaps(self, t1, t2):
        """Returns true if the path of the given tags overlaps"""
        m1 = self.get_prefix_l(t1)
        m2 = self.get_prefix_l(t2)
        return (t1 in m2) or (t2 in m1)

    def remove_overlaps(self, l): 
        """Returns list with overlapping tags removed"""
        if not l:
            return l
        pair_l = sorted([(self.get_depth(t),t) for t in l])
        out_l = [pair_l.pop()[1]]
        while pair_l:
            t = pair_l.pop()[1]
            if (not any(self.overlaps(t, e) for e in out_l)):
                out_l.append(t)
        return out_l

    def read_taxonomy(self, filepath):
        """Read taxonomy from given file"""
        with open(filepath, 'r') as fd:
            for line in fd:
                if line.startswith('#') or line == '\n':
                    continue
                self.add_tag(line.strip())
        return

    def to_file(self, filepath):
        """Output sorted taxonomy to given file"""
        # Open output file
        fd = open(filepath, 'w')
        # Write sorted tags
        tag_l = sorted(self._tag_map.items(), 
                                key=lambda item : item[1].path, 
                                reverse=False)
        idx = 0
        for name,tag in tag_l:
            if (idx % 2) == 0:
                fd.write(tag.path+"\n")
            idx+=1
        # Close output file
        fd.close()

class Rules:
    """A relation from one source to one or more destinations"""
    def __init__(self, filepath):
        """Initialize rule map and read rules from input file"""
        self._src_map = {} # src -> set(dst)
        if filepath:
            self.read_rules(filepath)

    def __len__(self):
        """The number of rules (i.e., source tags)"""
        return len(self._src_map)

    def add_rule(self, src, dst_l, overwrite=False):
        """Add rule.

        If rule exists:
        if overwrite==True, replace destination list
        else append dst_l to current target set
        """
        # Remove src from dst_l if it exists
        dst_l = filter(lambda x: x != src, dst_l)
        # If no destinations, nothing to do
        if (not dst_l):
            return
        log.debug("[Rules] Adding %s -> %s" % (src, dst_l))
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
        return

    def remove_rule(self, src):
        """Remove the rule for the input source"""
        l = self._src_map.get(src, [])
        if l:
            log.debug("[Rules] Removing rule: %s -> %s" % (src, l))
            del self._src_map[src]
            return 1
        else:
            return 0

    def get_dst(self, src):
        """Returns dst list for given src, or empty list if no expansion"""
        return list(self._src_map.get(src, []))

    def read_rules(self, filepath):
        """Read rules from given file"""
        with open(filepath, 'r') as fd:
            for line in fd:
                if line.startswith('#') or line == '\n':
                    continue
                word_list = line.strip().split()
                if len(word_list) > 1:
                    self.add_rule(word_list[0],word_list[1:])
        return

    def to_file(self, filepath, taxonomy=None):
        """Output sorted rules to given file
 
        If taxonomy is provided, it outputs full tag path
        """
        fd = open(filepath, 'w')
        for src,dst_set in sorted(self._src_map.items()):
            dst_l = sorted(dst_set, reverse=False)
            if taxonomy:
                src_path = taxonomy.get_path(src)
                path_l = [taxonomy.get_path(t) for t in dst_l]
                dst_str = '\t'.join(path_l)
                fd.write("%s\t%s\n" % (src_path,dst_str))
            else:
                dst_str = '\t'.join(dst_l)
                fd.write("%s\t%s\n" % (src,dst_str))
        fd.close()

    def expand_src_destinations(self, src):
        """Return a list of all expanded destinations for given source

           Recursively follows any rules for destinations
        """
        dst_set = self._src_map.get(src, set())
        out = set()
        while dst_set:
            dst = dst_set.pop()
            l = self._src_map.get(dst, [])
            if l:
                for e in l:
                    if (e not in out) and (e != dst):
                        dst_set.add(e)
            else:
                out.add(dst)
        return out

    def expand_all_destinations(self):
        """Expand all sources"""
        src_l = self._src_map.keys()
        for src in src_l:
            dst_l = self.expand_src_destinations(src)
            self._src_map[src] = dst_l

class Tagging(Rules):
    """A rule with an unknown source and a destination in the taxonomy"""
    def __init__(self, filepath):
        """Initialize rules from input file"""
        Rules.__init__(self, filepath)

    def validate(self, taxonomy):
        """Check that tags in tagging rules are in given taxonomy"""
        for src,dst_l in self._src_map.items():
            if taxonomy.is_tag(src):
                log.warning("[Tagging] SRC %s in taxonomy" % src)
            for t in dst_l:
                if (not taxonomy.is_tag(t)):
                    log.warning("[Tagging] %s not in taxonomy" % t)

    def build_synonymn_map(self):
        """Build a map from dst to src set from Tagging"""
        dst_map = {}
        for src, dst_set in self._src_map.items():
            for dst in dst_set:
                dst_map.setdefault(dst, set()).add(src)
        return dst_map

class Expansion(Rules):
    """A rule where source different than destination and both in taxonomy"""
    def __init__(self, filepath):
        Rules.__init__(self, filepath)

    def validate(self, taxonomy):
        """Check that tags in expansion rules are in given taxonomy"""
        for src,dst_set in self._src_map.items():
            if (not taxonomy.is_tag(src)):
                log.warning("[Expansion] %s not in taxonomy" % src)
            for dst in dst_set:
                if (not taxonomy.is_tag(dst)):
                    log.warning("[Expansion] %s not in taxonomy" % dst)

class AvLabels:
    """Primary class to process AV labels"""
    def __init__(
        self,
        tag_file=DEFAULT_TAG_PATH,
        exp_file = DEFAULT_EXP_PATH,
        tax_file = DEFAULT_TAX_PATH,
        av_l = None
    ):
        """Initialize using given files and options"""
        # Read taxonomy
        self.taxonomy = Taxonomy(tax_file)
        # Read tag rules
        self.tagging = Tagging(tag_file)
        # Read expansion rules
        self.expansions = Expansion(exp_file)
        # List of AV engines to use
        self.avs = av_l

    @staticmethod
    def is_pup(tag_pairs, taxonomy):
        """Whether the sample is PUP
 
           Checks if highest ranked CLASS tag contains "grayware"
           and is above a predefined threshold
           It returns False unless it can determine it is PUP
        """
        threshold = 0.5
        # If no tags, return false
        if len(tag_pairs) < 1:
            return False
        max_ctr = tag_pairs[0][1]
        for (tag,ctr) in tag_pairs:
            (path, cat) = taxonomy.get_info(tag)
            if (cat == "CLASS"):
                if ("grayware" in path):
                    return (float(ctr) >= float(max_ctr)*threshold)
                else:
                    return False
        return False

    @staticmethod
    def _remove_suffixes(av_name, label):
        """Returns input label without AV specific suffixes""" 
        # Truncate after last '.'
        if av_name in suffix_removal_av_set:
            label = label.rsplit('.', 1)[0]

        # Truncate after last '.' 
        # if suffix only contains digits or uppercase (no lowercase) chars
        if av_name == 'AVG':
            tokens = label.rsplit('.', 1)
            if len(tokens) > 1 and re.match("^[A-Z0-9]+$", tokens[1]):
                label = tokens[0]

        # Truncate after last '!'
        if av_name == 'Agnitum':
            label = label.rsplit('!', 1)[0]

        return label


    def get_label_tags(self, label, hashes):
        """Return list of tags in given label
 
           Tokenizes label, filters unneeded tokens, and 
           applies tagging rules
        """
        # Initialize set of tags to return
        # We use a set to avoid duplicate tokens in the same AV label
        # This avoids "potentially unwanted" contributing twice BEH:pup
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
            hash_token = False
            for hash_str in hashes:
                if hash_str[0:len(token)] == token:
                  hash_token = True
                  break
            if hash_token:
                continue

            # Ignore generic tokens
            if self.taxonomy.is_generic(token):
                continue

            # Apply tagging rule
            dst_l = self.tagging.get_dst(token)
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


    def _expand(self, tag_set):
        """Return expanded set of tags"""
        ret = set()
        for t in tag_set:
            # Include tag
            ret.add(t)

            # Include target of expansion rule in output
            ret.update(self.expansions.get_dst(t))

            # Include implicit expansions in taxonomy
            ret.update(self.taxonomy.expand(t))

        # Return a list for backwards compatibility 
        return ret

    def get_sample_tags(self, sample_info, expand=True):
        """Returns dictionary tag -> AV list of tags for the given sample"""

        # Initialize auxiliary data structures
        duplicates = set()
        av_dict = {}

        # Process each AV label
        for (av_name, label) in sample_info.labels:
            # If empty label, nothing to do
            if not label:
                continue

            ################
            # AV selection #
            ################
            if self.avs and av_name not in self.avs:
                continue

            #####################
            # Duplicate removal #
            #####################

            # Emsisoft uses same label as 
            # GData/ESET-NOD32/BitDefender/Ad-Aware/MicroWorld-eScan,
            # but suffixes ' (B)' to their label. Remove the suffix.
            if label.endswith(' (B)'):
                label = label[:-4]

            # F-Secure uses Avira's engine since Nov. 2018
            # but prefixes 'Malware.' to Avira's label. Remove the prefix.
            if label.startswith('Malware.'):
                label = label[8:]

            # Other engines often use exactly the same label, e.g.,
            #   AVG/Avast
            #   K7Antivirus/K7GW
            #   Kaspersky/ZoneAlarm

            # If we have seen the exact same label before, skip
            if label in duplicates:
                continue
            # If not, we add it to duplicates
            else:
                duplicates.add(label)

            ##################
            # Suffix removal #
            ##################
            label = self._remove_suffixes(av_name, label)

            ########################################################
            # Tokenization and tagging                             #
            ########################################################
            hashes = [ sample_info.md5, sample_info.sha1, sample_info.sha256 ]
            tags = self.get_label_tags(label, hashes)

            ########################################################
            # Expansions                                           #
            ########################################################
            if expand:
                expanded_tags = self._expand(tags)
            else:
                expanded_tags = tags

            ########################################################
            # Stores information that relates AV vendors with tags #
            ########################################################
            for t in expanded_tags:
                av_dict.setdefault(t, []).append(av_name)


        return av_dict

    def rank_tags(self, av_dict, threshold=1):
        """Return list of (tag, confidence) ranked by decreasing confidence

           Filters tags with less or equal threshold confidence
        """
        pairs = ((t, len(avs)) for (t,avs) in av_dict.items() 
                    if len(avs) > threshold)
        return sorted(pairs, key=itemgetter(1,0), reverse=True)

    def get_sample_vt_count(self, sample_info):
        """Return number of detections for sample using AV whitelist"""
        if self.avs is None:
            return len(sample_info.labels)
        else:
            cnt = 0
            for (av_name, label) in sample_info.labels:
                if av_name in self.avs:
                    cnt += 1
            return cnt

    def get_family_from_label(self, label):
        """Return family from given label, or None if no family found"""
        fam = None
        tags = self.get_label_tags(label, [])
        for t in tags:
            cat = self.taxonomy.get_category(t)
            if (cat == "FAM"):
                return t
            elif (cat == "UNK"):
                fam = t
        return fam

