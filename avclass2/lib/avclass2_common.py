#!/usr/bin/env python
'''
Main AVClass class
'''

import sys
import re
import string
import logging
from collections import OrderedDict as OrdDict
from collections import namedtuple
from operator import itemgetter, attrgetter

# Set logging
log = logging.getLogger(__name__)

# Prefix to identify platform tags
platform_prefix = "FILE:os:"

# Default category for tags in taxonomy with no category
uncategorized_cat  = "UNC"

SampleInfo = namedtuple('SampleInfo', 
                        ['md5', 'sha1', 'sha256', 'labels', 'vt_tags'])

# AVs to use in suffix removal
suffix_removal_av_set = {'Norman', 'Avast', 'Avira', 'Kaspersky',
                          'ESET-NOD32', 'Fortinet', 'Jiangmin', 'Comodo',
                          'GData', 'Avast', 'Sophos',
                          'TrendMicro-HouseCall', 'TrendMicro',
                          'NANO-Antivirus', 'Microsoft'}

class Tag:
    ''' A Tag in the taxonomy '''
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
        ''' Return hash '''
        return hash((self._path))

    @property
    def name(self):
        ''' Return tag name '''
        return self._name

    @property
    def cat(self):
        ''' Return tag category '''
        return self._cat

    @property
    def path(self):
        ''' Return tag path '''
        return self._path

    @property
    def prefix_l(self):
        ''' Return tag prefix list '''
        return self._prefix_l


class Taxonomy:
    '''
    A taxonomy of tags and generic tokens read from file
    '''
    def __init__(self, filepath):
        ''' Map tag.name | tag.path -> Tag '''
        self._tags = set()
        self._tag_map = {}
        if filepath:
            self.read_taxonomy(filepath)

    def __len__(self):
        ''' Taxonomy length is the number of tags it contains '''
        return len(self._tags)

    def __iter__(self):
        ''' Iterator over the alphabetically sorted tags in the taxonomy '''
        return (t for t in sorted(self._tags))

    def is_generic(self, t):
        ''' Return true if input is generic, false otherwise '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.cat == "GEN"
        else:
            return False

    def is_tag(self, t):
        ''' Return true if input is tag, false otherwise '''
        return t in self._tag_map

    def add_tag(self, s, override=False):
        ''' Add tag to taxonomy 
            If tag already exists with different path, 
              only replaces if override True '''
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
        ''' Remove tag from taxonomy. Returns 1 if removed, zero if unknown '''
        tag = self._tag_map.get(t, None)
        if tag:
            log.debug("[Taxonomy] Removing tag: %s" % tag.path)
            del self._tag_map[tag.name]
            del self._tag_map[tag.path]
            self._tags.remove(tag)
            return 1
        else:
            return 0

    def get_category(self, t):
        ''' Return category of input tag, UNK if not a tag '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.cat
        else:
            return "UNK"

    def get_path(self, t):
        ''' Return full path for given tag, or empty string if not a tag '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.path
        else:
            return ("UNK:" + t)

    def get_prefix_l(self, t):
        ''' Return prefix list for given tag, or empty string if not a tag '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.prefix_l
        else:
            return []

    def get_prefix(self, t):
        ''' Return prefix string for given tag, 
            or empty string if not a tag '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.prefix_l
        else:
            return t.path[0:t.path.rfind(':')]

    def get_depth(self, t):
        ''' Return depth of tag in taxonomy. 
            Returns zero if tag not in taxonomy. 
            A normal tag CAT:name has depth two '''
        tag = self._tag_map.get(t, None)
        if tag:
            return len(tag.prefix_l) + 2
        else:
            return 0

    def get_info(self, t):
        ''' Return (path,category) for given tag, or UNK:t if not a tag '''
        tag = self._tag_map.get(t, None)
        if tag:
            return tag.path, tag.cat
        else:
            return "UNK:" + t, "UNK"

    def expand(self, t):
        ''' Return list of tags in prefix list that are leaves '''
        tag = self._tag_map.get(t, None)
        if tag:
            return [t for t in tag.prefix_l if t in self._tag_map]
        else:
            return []

    def platform_tags(self): 
        ''' Returns list with platform tags in taxonomy '''
        acc = set()
        for idx,tag in self._tag_map.items():
            if tag.path.startswith(platform_prefix):
                acc.add(tag.name)
        return acc

    def overlaps(self, t1, t2):
        ''' Returns true if the path of the given tags overlaps '''
        m1 = self.get_prefix_l(t1)
        m2 = self.get_prefix_l(t2)
        return (t1 in m2) or (t2 in m1)

    def remove_overlaps(self, l): 
        ''' Returns list with overlapping tags removed '''
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
        '''Read taxonomy from given file '''
        with open(filepath, 'r') as fd:
            for line in fd:
                if line.startswith('#') or line == '\n':
                    continue
                self.add_tag(line.strip())
        return

    def to_file(self, filepath):
        ''' Output sorted taxonomy to given file '''
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
    '''
    Rules are src -> dst1, dst2, ... relations
    '''
    def __init__(self, filepath):
        ''' Map src -> set(dst) '''
        self._src_map = {}
        if filepath:
            self.read_rules(filepath)

    def __len__(self):
        ''' Length is number of rules, i.e., number of src '''
        return len(self._src_map)

    def add_rule(self, src, dst_l, overwrite=False):
        ''' Add rule. If rule exists:
            if overwrite==True, replace destination list
            else append dst_l to current target set  '''
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
        l = self._src_map.get(src, [])
        if l:
            log.debug("[Rules] Removing rule: %s -> %s" % (src, l))
            del self._src_map[src]
            return 1
        else:
            return 0

    def get_dst(self, src):
        ''' Returns dst list for given src, or empty list if no expansion '''
        return list(self._src_map.get(src, []))

    def read_rules(self, filepath):
        '''Read rules from given file'''
        with open(filepath, 'r') as fd:
            for line in fd:
                if line.startswith('#') or line == '\n':
                    continue
                word_list = line.strip().split()
                if len(word_list) > 1:
                    self.add_rule(word_list[0],word_list[1:])
        return

    def to_file(self, filepath, taxonomy=None):
        ''' Output sorted rules to given file 
            If taxonomy is provided, it outputs full tag path '''
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
        ''' Return destination list for given src after recursively 
            following any rules for destinations '''
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
        ''' Return destination list for given src after recursively 
            following any rules for destinations '''
        src_l = self._src_map.keys()
        for src in src_l:
            dst_l = self.expand_src_destinations(src)
            self._src_map[src] = dst_l

class Tagging(Rules):
    '''
    Tagging rules have src UNK and dst in taxonomy
    '''
    def __init__(self, filepath):
        Rules.__init__(self, filepath)

    def validate(self, taxonomy):
        ''' Check that tags in tagging rules are in given taxonomy '''
        for tok,tag_l in self._src_map.items():
            if taxonomy.is_tag(tok):
                sys.stdout.write("[Tagging] SRC %s in taxonomy\n" % tok)
            for t in tag_l:
                if (not taxonomy.is_tag(t)):
                    sys.stdout.write("[Tagging] %s not in taxonomy\n" % t)

class Expansion(Rules):
    '''
    Expansion rules have src and dst in taxonomy and
        src.category != dst.category
    '''
    def __init__(self, filepath):
        Rules.__init__(self, filepath)

    def validate(self, taxonomy):
        ''' Check that tags in expansion rules are in given taxonomy '''
        for src,dst_set in self._src_map.items():
            if (not taxonomy.is_tag(src)):
                sys.stdout.write("[Expansion] %s not in taxonomy\n" % src)
            for dst in dst_set:
                if (not taxonomy.is_tag(dst)):
                    sys.stdout.write("[Expansion] %s not in taxonomy\n" % dst)

class AvLabels:
    '''
    Class to operate on AV labels, 
    such as extracting the most likely family name.
    '''
    def __init__(self, tag_file, exp_file = None, tax_file = None,
                 av_file = None, aliasdetect=False):
        # Read taxonomy
        self.taxonomy = Taxonomy(tax_file)
        # Read tag rules
        self.tagging = Tagging(tag_file)
        # Read expansion rules
        self.expansions = Expansion(exp_file)
        # Read AV engines
        self.avs = self.read_avs(av_file) if av_file else None
        # Alias statistics initialization
        self.aliasdetect = aliasdetect

    @staticmethod
    def read_avs(avs_file):
        '''Read AV engine set from given file'''
        with open(avs_file) as fd:
            avs = set(map(str.strip, fd.readlines()))
        return avs

    @staticmethod
    def get_sample_info_lb(vt_rep):
        '''Parse and extract sample information from JSON line
           Returns a SampleInfo named tuple
        '''
        return SampleInfo(vt_rep['md5'], vt_rep['sha1'], vt_rep['sha256'],
                          vt_rep['av_labels'], [])

    @staticmethod
    def get_sample_info_vt_v2(vt_rep):
        '''Parse and extract sample information from JSON line
           Returns a SampleInfo named tuple
        '''
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
        '''Parse and extract sample information from JSON line
           Returns a SampleInfo named tuple
        '''
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
    def is_pup(tag_pairs, taxonomy):
        '''This function classifies the sample as PUP or not 
           by checking if highest ranked CLASS tag contains "grayware"
           and is above a predefined threshold
           Return:
              True/False/None
        '''
        threshold = 0.5
        # If no tags, return false
        if len(tag_pairs) < 1:
            return None
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
        '''Remove AV specific suffixes from given label
           Returns updated label'''

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
        ''' Return list of tags in given label 
            Tokenizes label, filters unneeded tokens, and 
            applies tagging rules '''

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
        ''' Return expanded set of tags '''
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

    def get_sample_tags(self, sample_info):
        ''' Returns dictionary tag -> AV list of tags for the given sample '''

        # Whitelist the AVs to filter the ones with meaningful labels
        av_whitelist = self.avs
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
            if av_whitelist and av_name not in av_whitelist:
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
            # NOTE: Avoiding to do expansion when aliases
            if self.aliasdetect:
                expanded_tags = tags
            else:
                expanded_tags = self._expand(tags)

            ########################################################
            # Stores information that relates AV vendors with tags #
            ########################################################
            for t in expanded_tags:
                av_dict.setdefault(t, []).append(av_name)


        return av_dict

    def rank_tags(self, av_dict, threshold=1):
        ''' Return list of (tag, confidence) ranked by decreasing confidence 
            and filter tags with less or equal threshold confidence '''

        pairs = ((t, len(avs)) for (t,avs) in av_dict.items() 
                    if len(avs) > threshold)
        return sorted(pairs, key=itemgetter(1,0), reverse=True)

