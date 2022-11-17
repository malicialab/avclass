# AVClass

AVClass is a malware labeling tool.

You give it as input the AV labels for a large number of 
malware samples (e.g., VirusTotal JSON reports) and it outputs the most 
likely family name for each sample that it can extract from the AV labels. 
It can also output a ranking of all alternative names it found for each sample.

The design and evaluation of AVClass is detailed in our 
[RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf):

> Marcos Sebastián, Richard Rivera, Platon Kotzias, and Juan Caballero. 
AVClass: A Tool for Massive Malware Labeling. 
In Proceedings of the International Symposium on Research in 
Attacks, Intrusions and Defenses,
September 2016.

In a nutshell, AVClass comprises two phases: 
preparation (optional) and labeling.
Code for both is included, 
but most users will be only interested in the labeling, which outputs the 
family name for the samples. 
The preparation produces a list of aliases and generic tokens 
used by the labeling. 
If you use our default aliases and generic tokens lists, 
you do not need to run the preparation.


## Labeling 
   
The labeler takes as input 
a JSON file with the AV labels of malware samples (-vt or -lb options), 
a file with generic tokens (-gen option), 
and a file with aliases (-alias option). 
It outputs the most likely family name for each sample.
If you do not provide alias or generic tokens files, 
the default ones in the *data* folder are used.

```shell
$./avclass_labeler.py -lb ../examples/malheurReference_lb.json -v > malheurReference.labels
```
  
The above command labels the samples whose AV labels are in the 
*../examples/malheurReference_lb.json* file.
It prints the results to stdout, 
which we redirect to the *malheurReference.labels* file.
The output looks like this:

```
aca2d12934935b070df8f50e06a20539 adrotator
67d15459e1f85898851148511c86d88d adultbrowser
```

which means sample aca2d12934935b070df8f50e06a20539 is most likely 
from the *adrotator* family and 
67d15459e1f85898851148511c86d88d from the *adultbrowser* family.

The verbose (-v) option makes it output an extra 
*malheurReference_lb.verbose* file
with all families extracted for each sample ranked by the number of AV 
engines that use that family.
The file looks like this:

```
aca2d12934935b070df8f50e06a20539  [(u'adrotator', 8), (u'zlob', 2)]
ee90a64fcfaa54a314a7b5bfe9b57357  [(u'swizzor', 19)]
f465a2c1b852373c72a1ccd161fbe94c  SINGLETON:f465a2c1b852373c72a1ccd161fbe94c
```

which means that for sample aca2d12934935b070df8f50e06a20539 
there are 8 AV engines assigning *adrotator* as the family and  
another 2 assigning *zlob*.
Thus, *adrotator* is the most likely family.
On the other hand, for ee90a64fcfaa54a314a7b5bfe9b57357 there are 19 AV 
engines assigning *swizzor* as family, 
and no other family was found.
The last line means that for sample f465a2c1b852373c72a1ccd161fbe94c
no family name was found in the AV labels. 
Thus, the sample is placed by himself in a singleton cluster 
with the name of the cluster being the sample's hash.

Note that the sum of the number of AV engines may not equal the number 
of AV engines with a label for that sample in the input file 
because the labels of some AV engines may only include generic tokens 
that are removed by AVClass.

## Input JSON format

AVClass supports three input JSON formats: 

1. VirusTotal v2 API JSON reports (*-vt file*), 
where each line in the input *file* should be the full JSON of a 
VirusTotal v2 API response to the */file/report* endpoint,
e.g., obtained by querying https://www.virustotal.com/vtapi/v2/file/report?apikey={apikey}&resource={hash}
There is an example VirusTotal v2 input file in examples/vtv2_sample.json

2. VirusTotal v3 API JSON reports (*-vt file -vt3*), 
where each line in the input *file* should be the full JSON of a VirusTotal API version 3 response with a *File* object report, 
e.g., obtained by querying https://www.virustotal.com/api/v3/files/{hash}
There is an example VirusTotal v3 input file in examples/vtv3_sample.json

3. Simplified JSON (*-lb file*),
where each line in *file* should be a JSON 
with (at least) these fields:
{md5, sha1, sha256, av_labels}. 
There is an example of such input file in *examples/malheurReference_lb.json*


**Multiple input files**

AVClass can handle multiple input files putting the results in the same output files 
(if you want results in separate files, process each input file separately).

It is possible to provide the -vt and -lb input options multiple times.

```shell
$./avclass_labeler.py -vt <file1> -vt <file2>
```
```shell
$./avclass_labeler.py -lb <file1> -lb <file2>
```

There are also -vtdir and -lbdir options that can be used to provide 
an input directory where all files are VT (-vtdir) or simplified (-lbdir) JSON reports:

```shell
$./avclass_labeler.py -vtdir <directory>
```

It is also possible to combine -vt with -vtdir and -lb with -lbdir, 
but you cannot combine input files of different format. Thus, this command works:

```shell
$./avclass_labeler.py -vt <file> -vtdir <directory>
```

But, this one throws an error:

```shell
$./avclass_labeler.py -vt <file1> -lb <file2>
```

## Labeling: Family Ranking

AVClass has a -fam option to output a file with a ranking of the 
families assigned to the input samples. 

```shell
$./avclass_labeler.py -lb ../examples/malheurReference_lb.json -v -fam > malheurReference.labels
```

will produce a file called *malheurReference_lb.families* with two columns:

```
virut 441
allaple 301
podnuha 300
```

indicating that 441 samples were classified in the virut family, 
301 as allaple, and 300 as podnuha.

This option is very similar to using the following shell command:

```shell
$cut -f 2 malheurReference.labels | sort | uniq -c | sort -nr
```

The main difference is that using the -fam option all SINGLETON samples, 
i.e., those for which no label was found, 
are grouped into a fake *SINGLETONS* family, 
while the shell command would leave each singleton as a separate family.


## Labeling: PUP Classification

AVClass also has a -pup option to classify a sample as
Potentially Unwanted Program (PUP) or malware.
This classification looks for PUP-related keywords
(e.g., pup, pua, unwanted, adware) in the AV labels and was proposed in our
[CCS 2015 paper](https://software.imdea.org/~juanca/papers/malsign_ccs15.pdf):

> Platon Kotzias, Srdjan Matic, Richard Rivera, and Juan Caballero.
Certified PUP: Abuse in Authenticode Code Signing.
In Proceedings of the 22nd ACM Conference on Computer and Communication Security, Denver, CO, October 2015

```shell
$./avclass_labeler.py -lb ../examples/malheurReference_lb.json -v -pup > malheurReference.labels
```

With the -pup option the output of the *malheurReference.labels* file
looks like this:

```
aca2d12934935b070df8f50e06a20539 adrotator 1
67d15459e1f85898851148511c86d88d adultbrowser 0
```

The digit at the end is a Boolean flag that 
indicates sample aca2d12934935b070df8f50e06a20539 is
(likely) PUP, but sample 67d15459e1f85898851148511c86d88d is (likely) not.

In our experience the PUP classification is conservative,
i.e., if it says the sample is PUP, it most likely is.
But, if it says that it is not PUP, it could still be PUP if the AV labels
do not contain PUP-related keywords.
Note that it is possible that some samples from a family get 
the PUP flag while other samples from the same family do not
because the PUP-related keywords may not appear in the labels of 
all samples from the same family. 
To address this issue, you can combine the -pup option with the -fam option.
This combination will add into the families file the classification of the 
family as malware or PUP, based on a majority vote among the samples in a 
family.

```shell
$./avclass_labeler.py -lb ../examples/malheurReference_lb.json -v -pup -fam > malheurReference.labels
```

will produce a file called *malheurReference_lb.families* with five columns:

```
# Family  Total Malware PUP FamType
virut 441 441 0 malware
magiccasino 173 0 173 pup
ejik  168 124 44  malware
```

For virut, the numbers indicate all the 441 virut samples are classified 
as malware, and thus the last column states that virut is a malware family. 
For magiccasino, all 173 samples are labeled as PUP, thus the family is PUP.
For ejik, out of the 168 samples, 124 are labeled as malware and 44 as PUP, 
so the family is classified as malware.


## Labeling: Ground Truth Evaluation

If you have ground truth for some malware samples, 
i.e., you know the true family for those samples, you can evaluate the accuracy of the labeling output by AVClass on those samples with respect to that 
ground truth.
The evaluation metrics used are precision, recall, and F1 measure.
See our RAID 2016 paper above for their definition.

```shell
$./avclass_labeler.py -lb ../examples/malheurReference_lb.json -v -gt ../examples/malheurReference_gt.tsv -eval > malheurReference.labels
```

The output includes these lines:

```
Calculating precision and recall
3131 out of 3131
Precision: 90.81  Recall: 94.05 F1-Measure: 92.40
```

The last line corresponds to the accuracy metrics obtained by 
comparing AVClass results with the provided ground truth.

Each line in the *../examples/malheurReference_gt.tsv* file has 
two **tab-separated** columns:

```
0058780b175c3ce5e244f595951f611b8a24bee2 CASINO
```

which indicates that sample 0058780b175c3ce5e244f595951f611b8a24bee2 
is known to be of the *CASINO* family.
Each sample in the input file should also appear in the ground truth file.
Note that the particular label assigned to each family does not matter. 
What matters is that all samples in the same family are assigned the 
same family name (i.e., the same string in the second column) 

The ground truth can be obtained from publicly available malware 
datasets. 
The one in *../examples/malheurReference_gt.tsv* comes from the 
[Malheur](http://www.mlsec.org/malheur/) dataset. 
There are other public datasets with ground truth such as 
[Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/) or 
[Malicia](http://malicia-project.com/dataset.html).


## Preparation: Generic Token Detection

The labeling takes as input a file with generic tokens that should be 
ignored in the AV labels, e.g., trojan, virus, generic, linux.
By default, the labeling uses the *data/default.generics* 
generic tokens file.
You can edit that file to add additional generic tokens you feel 
we are missing.

In our RAID 2016 paper we describe an automatic approach to 
identify generic tokens, which **requires ground truth**, 
i.e., it requires knowing the true family for each input sample.
Not only that, but **the ground truth should be large**, 
i.e., contain at least one hundred thousand samples. 
In our work we identified generic tokens using as ground truth 
the concatenation of all datasets for which we had ground truth.
This requirement of a large ground truth dataset is why we expect most users 
will skip this step and simply use our provided default file.

If you want to test generic token detection you can do:

```shell
 $./avclass_generic_detect.py -lb ../examples/malheurReference_lb.json -gt ../examples/malheurReference_gt.tsv -tgen 10 > malheurReference.gen 
```

Each line in the *../examples/malheurReference_gt.tsv* file has 
two **tab-separated** columns:

```
0058780b175c3ce5e244f595951f611b8a24bee2 CASINO
```

which indicates that sample 0058780b175c3ce5e244f595951f611b8a24bee2 
is known to be of the *CASINO* family.

The *-tgen 10* option is a threshold for the minimum number of families 
where a token has to be observed to be considered generic. 
If the option is ommitted, the default threshold of 8 is used.

The above command outputs two files: 
*malheurReference.gen* and *malheurReference_lb.gen*. 
Each of them has 2 columns: token and number of families where the token 
was observed.
File *malheurReference.gen* is the final output with the detected 
generic tokens for which the number of families is above 
the given threshold. 
The file *malheurReference_lb.gen* has this information for all tokens.
Thus, *malheurReference.gen* is a subset of *malheurReference_lb.gen*. 

However, note that in the above command you are trying to identify generic 
tokens from a small dataset since Drebin only contains 3K labeled samples. 
Thus, *malheurReference.gen* only contains 25 identified generic tokens. 
Using those 25 generic tokens will produce significantly worse results 
than using the generic tokens in *data/default.generics*. 
For more details you can refer to our RAID 2016 paper.


## Preparation: Alias Detection

Different vendors may assign different names (i.e., aliases) for the same
family. For example, some vendors may use *zeus* and others *zbot* 
as aliases for the same malware family. 
The labeling takes as input a file with aliases that should be merged.
By default, the labeling uses the *data/default.aliases* aliases file.
You can edit that file to add additional aliases you feel we are missing.

In our RAID 2016 paper we describe an automatic approach 
to identify aliases.
Our alias detection approach 
**requires as input the AV labels for large set of samples**, 
e.g., several million samples. 
In contrast with the generic token detection, the input samples for 
alias detection **do not need to be labeled**, 
i.e., no need to know their family.
In our work we identified aliases using as input the largest of our 
unlabeled datasets, which contained nearly 8M samples. 
This requirement of a large input dataset is why we expect most users
will skip this step and simply use our provided default file.

If you want to test alias detection you can do:

```shell
$./avclass_alias_detect.py -lb ../examples/malheurReference_lb.json -nalias 100 -talias 0.98 > malheurReference.aliases
```

The -nalias threshold provides the minimum number of samples two tokens 
need to be observed in to be considered aliases. 
If the option is not provided the default is 20.

The -talias threshold provides the minimum fraction of times that 
the samples appear together.
If the  is not provided the default is 0.94 (94%).

The above command outputs two files:
*malheurReference.aliases* and *malheurReference_lb.alias*.
Each of them has 6 columns: 
1. t1: token that is an alias
2. t2: family for which t1 is an alias
3. |t1|: number of input samples where t1 was observed
4. |t2|: number of input samples where t2 was observed
5. |t1^t2|: number of input samples where both t1 and t2 were observed
6. |t1^t2|/|t1|: ratio of input samples where both t1 and t2 
were observed over the number of input samples where t1 was observed.

File *malheurReference.aliases* is the final output with the 
detected aliases that satisfy the -nalias and -talias thresholds.
The file *malheurReference_lb.alias* has this information for all tokens.
Thus, *malheurReference.aliases* is a subset 
of *malheurReference_lb.alias*.

However, note that in the above command you are trying to identify aliases
from a small dataset since Drebin only contains 3K samples.
Thus, *malheurReference.aliases* only contains 6 identified aliases. 
Using those 6 aliases will produce significantly worse results than using 
the aliases in *data/default.aliases*.
As mentioned, to improve the identified aliases you should provide as 
input several million samples.
For more details you can refer to our RAID 2016 paper.

