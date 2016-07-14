# AVClass

[AVClass](https://github.com/malicialab/avclass) 
is a malware labeling tool.

You give it as input the AV labels for a large number of 
malware samples (e.g., VirusTotal JSON reports) and it outputs the most 
likely family name for each sample that it can extract from the AV labels. 
It can also output a ranking of all alternative names it found for each sample.

The design and evaluation of AVClass is detailed in our 
[RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf):

> M.Sebastián, R. Rivera, P. Kotzias, and J. Caballero. AVClass: A tool for
Massive Malware Labeling. In International Symposium on Research in Attacks,
Intrusions and Defenses, September 2016.

In a nutshell, AVClass comprises two phases: 
preparation (optional) and labeling.
Code for both is included, 
but most users will be only interested in the labeling, which outputs the 
family name for the samples. 
The preparation produces a list of aliases and generic tokens 
used by the labeling. 
If you use our default aliases and generic tokens lists, 
you do not need to run the preparation.

**Why is AVClass useful?**

Because a lot of times security researchers want to extract family information 
from AV labels, but this process is not as simple as it looks, 
especially if you need to do it for large numbers (e.g., millions) of 
samples. Some advantages of AVClass are:

1. *Automatic.* 
  AVClass removes manual analysis limitations on the size of the input dataset.

2. *Vendor-agnostic.*
  AVclass operates on the labels of any available set of AV engines, which can vary from sample to sample.

3. *Cross-platform.*
  AVclass can be used for any platforms supported by AV engines, 
  e.g., Windows or Android malware.

4. *Does not require executables.*
  AV labels can be obtained from online services like VirusTotal using a sample's hash, even when the executable is not available.

5. *Quantified accuracy.* 
  We have evaluated AVClass on 5 publicly available malware datasets with 
  ground truth. Details are in the above RAID 2016 paper. 

6. *Open source.*
  The code is available and we are happy to incorporate suggestions and 
  improvements so that the security community benefits from AVClass.

**Limitations**

The main limitation of AVClass is that its output depends on the input 
AV labels. 
It tries to compensate for the noise on those labels, but 
cannot identify the family of a sample if AV engines do not provide 
non-generic family names to that sample. 
In particular, it cannot label samples if at least 2 AV engines 
do not agree on a non-generic family name. 
Results on 8 million samples showed that AVClass could label 81% of the 
samples. 
In other words, it could not label 19% of the 
samples because their labels contained only generic tokens.

Still, there are many samples that AVClass can label and thus we believe 
you will find it a useful tool. 
We recommend you to read the discussion section in our RAID 2016 paper for 
more details.

## Labeling 
   
  The labeler takes as input 
  a JSON file with the AV labels of malware samples (-vt or -lb switches), 
  a file with generic tokens (-gen switch), 
  and a file with aliases (-alias switch). 
  It outputs the most likely family name for each sample.
  If you do not provide alias or generic tokens files, 
  the default ones in the *data* folder are used.

  ```
  $./avclass_labeler.py -lb data/samples.json -v > samples.labels
  ```
  
  The above command labels the samples whose AV labels are in the 
  *data/samples.json* file.
  It prints the results to stdout, 
  which we redirect to the *samples.labels* file.
  The output looks like this:

  ```
  1fa3cfb35de9e82111fd45ad14de75d9  loadmoney
  1fa3ccb218ee40e970234b04d4c9a8fd  vobfus
  ```

  which means sample 1fa3cfb35de9e82111fd45ad14de75d9 is most likely from the 
  *loadmoney* family and 
  1fa3ccb218ee40e970234b04d4c9a8fd from the *vobfus* family.

  The verbose (-v) switch makes it output an extra *samples.verbose* file
  with all families extracted for each sample ranked by the number of AV 
  engines that use that family.
  The file looks like this:

  ```
  1fa3cfb35de9e82111fd45ad14de75d9        [(u'loadmoney', 7), (u'hype', 2), (u'badur', 2)]
  1fa3ccb218ee40e970234b04d4c9a8fd        [('vobfus', 16)]
  ```

  which means that for sample 1fa3cfb35de9e82111fd45ad14de75d9 
  there are 7 AV engines assigning *loadmoney* as the family, 
  another 2 assigning *hype*, and another 2 assigning *badur*.
  Thus, *loadmoney* is the most likely family.
  On the other hand, for 1fa3ccb218ee40e970234b04d4c9a8fd there are 16 AV 
  engines assigning *vobfus* as family, and no other family candiate was found.

  Note that the sum of the number of AV engines may not equal the number of 
  AV engines with a label in the input file for that sample 
  because the labels of some AV engines may only include generic tokens 
  that are removed by AVClass.


## Input JSON format

AVClass supports two input JSON formats: 

1. VirusTotal JSON reports (*-vt file*), 
where each line in *file* should be the full JSON of a 
VirusTotal report as fetched through the VirusTotal API.

2. Simplified JSON (*-lb file*),
where each line in *file* should be a JSON 
with (at least) these fields:
{md5, sha1, sha256, scan_date, av_labels}. 
There is an example of such input file in *data/samples.json*

**Why have 2 different input formats?**

We believe most users will get the AV labels using VirusTotal. 
However, AVClass is IO-bound and a VirusTotal report 
in addition to the AV labels and hashes includes 
much other data that AVClass does not need. 
Thus, when applying AVClass to millions of samples,
reducing the input file size by removing unnnecessary data 
significantly improves efficiency. 
Furthermore, users could obtain AV labels from other sources and 
the simpler the input JSON format, 
the easier to convert those AV labels into an input file.

At this point you have read the most important information on how to use 
AVClass. 
The following sections describe steps that most users will not need.

## Preparation: Generic Token Detection

The labeling takes as input a file with generic tokens that should be 
ignored in the AV labels, e.g., trojan, virus, generic, linux.
By default, the labeling uses the *data/default.generics* generic tokens file.
You can edit that file to add additional generic tokens you feel we are missing.

In our RAID 2016 paper we describe an automatic approach to identify generic 
tokens, which requires ground truth, 
i.e., it requires knowing the true family for each input sample.
That is why we expect most users will skip this step and simply use our 
provided default file.
But, if you want to test it you can do:

   ```
   $./avclass_generic_detect.py -lb data/samples.json -gt ground.truth -tgen 10 > samples.gen 
   ```
  
  Each line in the *ground.truth* file should have two **tab-separated** 
  columns:

  ```
  1fa3cfb35de9e82111fd45ad14de75d9 loadmoney
  ```

  which indicates that sample 1fa3cfb35de9e82111fd45ad14de75d9 is known to be
  of the *loadmoney* family.

  The *-tgen 10* switch is a threshold for the minimum number of families 
  where a token has to be observed to be considered generic. 
  If the switch is ommitted, the default threshold of 8 is used.

  For more details on this threshold, you can refer to our RAID 2016 paper.

## Preparation: Alias Detection

Different vendors may assign different names (i.e., aliases) for the same
family. For example, some vendors may use *zeus* and others *zbot* 
as aliases for the same malware family. 
The labeling takes as input a file with aliases that should be merged.
By default, the labeling uses the *data/default.aliases* aliases file.
You can edit that file to add additional aliases you feel we are missing.

In our RAID 2016 paper we describe an automatic approach to identify aliases.
We expect most users will skip this step and simply use our 
provided default file.
But, if you want to test it you can do:

   ```
   $./avclass_alias_detect.py -lb data/samples.json -nalias 100 -talias 0.98 > samples.aliases
   ```

  The -nalias threshold provides the minimum number of samples two tokens 
  need to be observed in to be considered aliases. 
  If the switch is not provided the default is 20.

  The -talias threshold provides the minimum fraction of times that 
  the samples appear together.
  If the switch is not provided the default is 0.94 (94%).

  For more details on these thresholds, you can refer to our RAID 2016 paper.


## Ground truth evaluation

If you have ground truth for some malware samples, 
i.e., you know the true family for those samples, you can evaluate the accuracy of the labeling output by AVClass on those samples with respect to that 
ground truth.
The evaluation metrics used are precision, recall, and F1 measure.
See our RAID 2016 paper above for their definition.

  ```
  $./avclass_labeler.py -lb data/samples.json -v -gt ground.truth -eval > samples.labels
  ```

  Each line in the *ground.truth* file should have two **tab-separated** 
  columns:

  ```
  1fa3cfb35de9e82111fd45ad14de75d9 loadmoney 
  ```

  which indicates that sample 1fa3cfb35de9e82111fd45ad14de75d9 is known to be 
  of the *loadmoney* family.
  Note that the particular label assigned to each family does not matter. 
  What is important is that all samples in the same family are assigned the 
  same label (i.e., the same string in the second column) 
  
  The ground truth can be obtained from publicly available malware datasets 
  such as 
  [Malheur](http://www.mlsec.org/malheur/), 
  [Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/), or 
  [Malicia](http://malicia-project.com/dataset.html).



## Contributors

Several members of the MaliciaLab at the 
[IMDEA Software Institute](http://software.imdea.org) 
have contributed code to AVClass including:
Marcos Sebastián, Richard Rivera, Platon Kotzias, Srdjan Matic, and Juan Caballero.

