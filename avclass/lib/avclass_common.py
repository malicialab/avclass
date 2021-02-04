#!/usr/bin/env python
'''
Main AVClass class
'''

import re
import string
from collections import OrderedDict as OrdDict
from collections import namedtuple
from operator import itemgetter, attrgetter

SampleInfo = namedtuple('SampleInfo', 
                        ['md5', 'sha1', 'sha256', 'labels'])

# AVs to use in is_pup method
pup_av_set = {'Malwarebytes', 'K7AntiVirus', 'Avast',
              'AhnLab-V3', 'Kaspersky', 'K7GW', 'Ikarus',
              'Fortinet', 'Antiy-AVL', 'Agnitum', 'ESET-NOD32'}

# Tokens that indicate PUP used by is_pup method
pup_tokens = {'PUA', 'Adware', 'PUP', 'Unwanted', 'Riskware', 'grayware',
              'Unwnt', 'Adknowledge', 'toolbar', 'casino', 'casonline',
              'AdLoad', 'not-a-virus'}

# AVs to use in suffix removal
suffix_removal_av_set = {'Norman', 'Avast', 'Avira', 'Kaspersky',
                          'ESET-NOD32', 'Fortinet', 'Jiangmin', 'Comodo',
                          'GData', 'Avast', 'Sophos',
                          'TrendMicro-HouseCall', 'TrendMicro',
                          'NANO-Antivirus', 'Microsoft'}

class AvLabels:
    '''
    Class to operate on AV labels, 
    such as extracting the most likely family name.
    '''
    def __init__(self, gen_file = None, alias_file = None, av_file = None):

        # Read generic token set from file
        self.gen_set = self.read_generics(gen_file) if gen_file else set()

        # Read aliases map from file
        self.aliases_map = self.read_aliases(alias_file) if alias_file else {}

        # Read AV engine set from file
        self.avs = self.read_avs(av_file) if av_file else None

    @staticmethod
    def read_aliases(alfile):
        '''Read aliases map from given file'''
        if alfile is None:
            return {}
        almap = {}
        with open(alfile, 'r') as fd:
            for line in fd:
                alias, token = line.strip().split()[0:2]
                almap[alias] = token
        return almap

    @staticmethod
    def read_generics(generics_file):
        '''Read generic token set from given file'''
        gen_set = set()
        with open(generics_file) as gen_fd:
            for line in gen_fd:
                if line.startswith('#') or line == '\n':
                    continue
                gen_set.add(line.strip())
        return gen_set

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
                          vt_rep['av_labels'])

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

        return SampleInfo(md5, sha1, sha256, label_pairs)

    @staticmethod
    def get_sample_info_vt_v3(vt_rep):
        '''Parse and extract sample information from JSON line
           Returns a SampleInfo named tuple
        '''
        label_pairs = []
        # Obtain scan results, if available
        try:
            scans = vt_rep['data']['attributes']['last_analysis_results']
            md5 = vt_rep['data']['attributes']['md5']
            sha1 = vt_rep['data']['attributes']['sha1']
            sha256 = vt_rep['data']['attributes']['sha256']
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

        return SampleInfo(md5, sha1, sha256, label_pairs)

    @staticmethod
    def is_pup(av_label_pairs):
        '''This function classifies the sample as PUP or not 
           using the AV labels as explained in the paper:
           "Certified PUP: Abuse in Authenticode Code Signing" 
           (ACM CCS 2015)
           It uses the AV labels of 11 specific AVs. 
           The function checks for 13 keywords used to indicate PUP.
           Return:
              True/False/None
        '''
        # If no AV labels, nothing to do, return
        if not av_label_pairs:
            return None
        # Initialize
        pup = False
        threshold = 0.5
        # Set with (AV name, Flagged/not flagged as PUP), for AVs in pup_av_set
        bool_set = set([(pair[0], t.lower() in pair[1].lower()) 
                        for t in pup_tokens
                        for pair in av_label_pairs
                        if pair[0] in pup_av_set])

        # Number of AVs that had a label for the sample
        av_detected = len([p[0] for p in av_label_pairs
                           if p[0] in pup_av_set])

        # Number of AVs that flagged the sample as PUP
        av_pup = list(map(lambda x: x[1], bool_set)).count(True)

        # Flag as PUP according to a threshold
        if (float(av_pup) >= float(av_detected)*threshold) and av_pup != 0:
            pup = True
        return pup


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
        if av_name in set(['Agnitum','McAffee','McAffee-GW-Edition']):
            label = label.rsplit('!', 1)[0]

        # Truncate after last '('
        if av_name in set(['K7AntiVirus', 'K7GW']):
            label = label.rsplit('(', 1)[0]

        # Truncate after last '@'
        # GData would belong here, but already trimmed earlier
        if av_name in set(['Ad-Aware', 'BitDefender', 'Emsisoft', 'F-Secure', 
                          'Microworld-eScan']):
            label = label.rsplit('(', 1)[0]

        return label


    def _normalize(self, label, hashes):
        '''Tokenize label, filter tokens, and replace aliases'''

        # If empty label, nothing to do
        if not label:
            return []

        # Initialize list of tokens to return
        ret = []

        # Split label into tokens and process each token
        for token in re.split("[^0-9a-zA-Z]", label):
            # Convert to lowercase
            token = token.lower()

            # Remove digits at the end
            end_len = len(re.findall("\d*$", token)[0])
            if end_len:
                token = token[:-end_len]

            # Ignore short token
            if len(token) < 4:
                continue

            # Remove generic tokens
            if token in self.gen_set:
                continue

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

            # Replace alias
            token = self.aliases_map[token] if token in self.aliases_map \
                                            else token

            # Add token
            ret.append(token)
        return ret

    def get_family_ranking(self, sample_info):
        '''
        Returns sorted dictionary of most likely family names for sample
        '''
        # Extract info from named tuple
        av_label_pairs = sample_info[3]
        hashes = [ sample_info[0], sample_info[1], sample_info[2] ]

        # Whitelist the AVs to filter the ones with meaningful labels
        av_whitelist = self.avs

        # Initialize auxiliary data structures
        labels_seen = set()
        token_map = {}

        # Process each AV label
        for (av_name, label) in av_label_pairs:
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
            if label in labels_seen:
                continue
            # If not, we add it to the set of labels seen
            else:
                labels_seen.add(label)

            ##################
            # Suffix removal #
            ##################
            label = self._remove_suffixes(av_name, label)

            ########################################################
            # Tokenization, token filtering, and alias replacement #
            ########################################################
            tokens = self._normalize(label, hashes)

            # Increase token count in map
            for t in tokens:
                c = token_map[t] if t in token_map else 0
                token_map[t] = c + 1

        ##################################################################
        # Token ranking: sorts tokens by decreasing count and then token #
        ##################################################################
        sorted_tokens = sorted(token_map.items(), 
                                key=itemgetter(1,0), 
                                reverse=True)

        # Delete the tokens appearing only in one AV, add rest to output
        sorted_dict = OrdDict()
        for t, c in sorted_tokens:
            if c > 1:
                sorted_dict[t] = c
            else:
                break
        
        return sorted_dict

