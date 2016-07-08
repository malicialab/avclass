# AVClass

AVClass is an automatic labeling tool that given the AV labels for a,
potentially massive, number of samples outputs the most likely family names
for each sample. It can also be used for clustering malware when a 
state-of-the-art clustering system is not available.

AVClass comprises two phases: preparation (optional) and labeling.
During the preparation phase, an analyst runs the generic token detection and
alias detection modules on the AV labels of a large number of samples to produce
lists of generic tokens and aliases, which become inputs to the labeling phase.
The preparation phase is optional since AVClass includes default lists of
generic tokens and aliases obtained from 8.9M samples included in 10 datasets.

The labeling phase is the core of AVClass and implements the label 
normalization process. It takes as input the AV labels of a large number of
samples to be labeled, a list of generic tokens, a list of aliases, and 
optionally a list of AV engines to use. By default, AVClass uses all AV engines
in the set of AV labels for a sample. For each sample to be labeled, it outputs
a ranking of its most likely family names.

Detailed analysis of each module along with the evaluation of the AVClass tool
can be found in our RAID2016 paper [1].


AVClass includes:
    
    avclass_generic_detect.py: (optional) Given a set of AV labels and the family
                                  names of the samples it generates a list of generic tokens.

    avclass_alias_detect.py:   (optional) Given a collection of AV labels it generates
                                  a list of alias pairs.

    avclass_labeler.py:        Given a collection of AV labels it generates the family
                               names of the samples.

######AV Labels format:

All modules included in AVClass require as input the AV labels for a collection
of samples. Input file can be either:
```
   a) A file where each line is a JSON of a VirusTotal report 
      as fetched by the VirusTotal API (-vt)
    
   b) A file where each line is a JSON with at least the following 
     fields {md5, sha1, sha256,scan_date,av_labels} (-lb)
```
See samples/ directory for examples of both formats.

*Note: It is recommended for large datasets to use option b) that significantly
improves the performance of the tool.*


### Preparation Phase (optional)

Preparation phase in optional. AVClass uses by default our own generic tokens and aliases extracted from 8.9M 
malware samples.


1) **Generic token detection**

   AV labels typically contain multiple generic tokens that are not specific to 
   a family (e.g., Win32, Adware, Trojan etc.).
   This module is used to automatically build a list of generic tokens.
   When AVClass tries to select a label for a sample, any token included in the
   generic tokens list is ignored since it's not family-specific.
   Generic token detection requires the family names for the samples (-gt).

   Usage:
   ```
   $./avclass_generic_detect.py -vt dataset.json -gt dataset_gt.csv > dataset.gen 
   ```
   
  *Note: Generic token detection uses a threshold (-tgen) for the 
        minimum number of families that a token appears. Any token appearing
        more families than Tgen is considered generic. Defaul value: 8.*


2) **Alias detection**

   Different vendors may assign different names (i.e., aliases) for the same
   family. For example, some vendors may use zeus and other zbot as aliases for
   the same malware family. This module is used to automatically build a list
   of aliases. The module requires as input the generic token list.
   When AVClass tries to select a label for a sample tokens that are included
   in the aliases list are replaced by their most prevalent name.

   Usage:
   ```
   $./avclass_alias_detect.py -vt dataset.json -gen dataset.gen > dataset.aliases
   ```
  *Note: Alias detection module uses two thresholds, the Nalias (-nalias)
        and the Talias (-talias). Nalias is the minimum number of times
        the pair of tokens have been seen and Talias is the minimum percentage
        of times the pair of tokens appear together. Default values are:
        Nalias=20 and Talias=0.94.*



### Labeling Phase
   
   The labeling phase is the core of AVClass and implements the label normalization process.
   The labeler takes as input the AV labels of a large dataset of 
   malware (-vt or -lb) along with a list of generic tokens 
   and a list of aliases and generates a family name for each sample.

   Usage:
   ```
   $./avclass_labeler.py -lb datasets/mal_dataset.json > dataset.labels 2> dataset.stderr
   ```

   Extra options:

     - Verbose parameter (-v) outputs an extra file (dataset.verbose) that all labels per sample
     - The -eval parameter can be used for evaluating the clustering accuracy of AVClass
       against an already clustered dataset (provided using the -gt parameter).

### Why use AVClass?

AVClass combines some interesting features:

1. **Automatic.** 
  AVClass removes manual analysis limitations on the size of the input dataset.

2. **Vendor-agnostic.**
  AVclass operates on the labels of any available set of AV engines, which can vary from sample to sample.

3. **Cross-platform.**
  AVclass can be used for any platforms supported by AV engines.

4. **Does not require executables.** 
  AV labels can be obtained from online services like VirusTotal using a sample's hash, even when the executable is not available.


### Limitations
Before using AVClass you should be aware of its limitations:

1. AVClass can be as good as the AV labels are. AVClass cannot identify a family
   if it's not contained in an AV label. It cannot label samples if at least
   2 AV engines do not agree on a non-generic family name. Results on the largest
   dataset we used in our evaluation shows that AVClass cannot label 19% of the samples,
   typically because those labels contain only generic tokens.

2. Clustering accuracy. AVClass was designed as a malware labeling tool. While
   it can be used for clustering malware, its evaluated precision is 87.2%-95.3%.
   Thus, AVClass should only be used for clustering when a state-of-the-art
   clustering system is not available and implementing one is not worth the 
   effort (despite improved accuracy).

### Dependencies

AVClass requires Python2.7

### Contributors

Marcos Sebastián

Richard Rivera

Platon Kotzias

Juan Caballero




### Further Reading

1. M.Sebastián, R. Rivera, P. Kotzias, and J. Caballero. AVClass: A tool for
Massive Malware Labeling. In International Symposium on Research in Attacks,
Intrusions and Defenses, September 2016.
