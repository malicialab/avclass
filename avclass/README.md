# AVClass2

AVClass2 is a malware tagging tool. It extends AVClass to extract from AV labels not only family name tags, but other tags capturing the malware class (e.g., *worm*, *ransomware*, *grayware*), behaviors (e.g., *spam*, *ddos*), and file properties (e.g., *packed*, *themida*, *bundle*, *nsis*). 

You give it as input the AV labels for a large number of malware samples (e.g., VirusTotal JSON reports)
and it outputs tags observed in the AV labels, ranked by decreasing popularity. 

The design and evaluation of AVClass2 is detailed in our ACSAC 2020 paper.

> Silvia Sebastián, Juan Caballero. 
AVClass2: Massive Malware Tag Extraction from AV Labels. 
In proceedings of the Annual Computer Security Applications Conference, December 2020.

In a nutshell, AVClass2 comprises two modules: labeling and update. Code for both is included, but most users will be only interested in the labeling, which outputs the tags for the samples. The update module is used to update the input taxonomy, tagging rules, and expansion rules. If you use our default taxonomy, tagging, and expansion files, you do not need to run the update module.


## Labeling

The labeler takes as input a JSON file with the AV labels of malware samples 
(-vt or -lb options), 
a file with the taxonomy (-tax option), 
a file with tagging rules (-tag option), and
a file with expansion rules (-exp option). 
It outputs a set of ranked tags. 
If you do not provide taxonomy, expansion or tagging files, 
the default ones in the data folder are used.

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json
```

The above command labels the samples whose AV labels are in 
the ../examples/malheurReference_lb.json file. 
It prints the results to stdout. 
The output looks like this: 

```
aca2d12934935b070df8f50e06a20539 33 grayware|10,adware|9,windows|8,adrotator|8,downloader|3,zlob|2
67d15459e1f85898851148511c86d88d 37 dialer|23,windows|9,adultbrowser|8,porndialer|7,grayware|6,tool|3,target|2
```

which means sample *aca2d12934935b070df8f50e06a20539* 
was flagged by 33 AV engines and 10 of them agree it is *grayware*, 9 that it is more specifically *adware*, 
8 mention that it runs on *windows*, another 8 that it is the *adrotator* family, 
3 that it is a *downloader*, and 2 that it belongs instead to the *zlob* family.
Sample *67d15459e1f85898851148511c86d88d* is flagged by 37 AV engines and 23 of them 
consider it a *dialer*, 8 that it belongs to the *adultbrowser* family, and so on. 

The -p option outputs the full path of each tag in the taxonomy: 

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json -p
```

The above command line outputs:

```
aca2d12934935b070df8f50e06a20539 33 CLASS:grayware|10,CLASS:grayware:adware|9,FILE:os:windows|8,FAM:adrotator|8,CLASS:downloader|3,FAM:zlob|2
67d15459e1f85898851148511c86d88d 37 CLASS:dialer|23,FILE:os:windows|9,FAM:adultbrowser|8,CLASS:dialer:porndialer|7,CLASS:grayware|6,CLASS:grayware:tool|3,FAM:target|2
```

where each tag has been replaced by its taxonomy path, which starts with the category in capitals, 
followed by the path in the category (if any), and the tag itself, all separated by colons. 
For example, *FAM:adrotator* makes explicit that *adrotator* is a malware family, 
*CLASS:grayware* that *grayware* is a malware class, and 
*CLASS:grayware:adware* that *adware* is a subclass of *grayware*.

**Compatibility mode**

The compatibility -c option makes AVClass2 output the same format as AVClass. 

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json -c
```

outputs:

```
bb23e1d296cf01bbaf32ed3938f9b0b8 allaple
cc4521ea738e8ba17139f86b3def5349 SINGLETON:cc4521ea738e8ba17139f86b3def5349
```

As in AVClass, the output contains only the family name, 
which corresponds to the highest ranked family tag, all other tags are ignored.
Samples for which a family cannot be obtained are labeled as singletons with their hash.
 
It is important to note that AVClass2 compatibility mode results can differ from AVClass results
on the same input file.
The differences in family names are due to differences between the generics and aliases files 
used by AVClass and the taxonomy, tagging rules, and expansion rules used by AVClass2. 
In the future, we may change AVClass to use the taxonomy and rules from AVClass2 
as input (instead of the generics and aliases files) 
to minimize such differences and avoid maintaining different data files.


## Input JSON format

AVClass2 supports three input JSON formats:

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

AVClass2 can handle multiple input files putting the results in the same output files 
(if you want results in separate files, process each input file separately).

It is possible to provide the -vt and -lb input options multiple times.

```shell
$./avclass2_labeler.py -vt <file1> -vt <file2>
```
```shell
$./avclass2_labeler.py -lb <file1> -lb <file2>
```

There are also -vtdir and -lbdir options that can be used to provide 
an input directory where all files are VT (-vtdir) or simplified (-lbdir) JSON reports:

```shell
$./avclass2_labeler.py -vtdir <directory>
```

It is also possible to combine -vt with -vtdir and -lb with -lbdir, 
but you cannot combine input files of different format. Thus, this command works:

```shell
$./avclass2_labeler.py -vt <file> -vtdir <directory>
```

But, this one throws an error:

```shell
$./avclass2_labeler.py -vt <file1> -lb <file2>
```

At this point you have read the most important information on how to use AVClass2. 
The following sections describe steps that most users will not need.

## Labeling: Ground Truth Evaluation

If you have family ground truth for some malware samples, i.e., 
you know the true family for those samples, you can evaluate the accuracy 
of the family tags output by AVClass2 on those samples with respect to that ground truth. 
The evaluation metrics used are precision, recall, and F1 measure. 
See our [RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf) for their definition.
Note that the ground truth evaluation does not apply to non-family tags, 
i.e., it only evaluates the output of the compatibility mode.

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json -gt ../examples/malheurReference_gt.tsv > malheurReference.labels
```

The output includes these lines:

```
Calculating precision and recall
3131 out of 3131
Precision: 90.81  Recall: 94.05 F1-Measure: 92.40
```

Each line in the *../examples/malheurReference_gt.tsv* file has two **tab-separated** columns:

```
aca2d12934935b070df8f50e06a20539 ADROTATOR
```

which indicates that sample aca2d12934935b070df8f50e06a20539 is known 
to be of the *ADROTATOR* family. 
Each sample in the input file should also appear in the ground truth file. 
Note that the particular label assigned to each family does not matter. 
What matters is that all samples in the same family are assigned 
the same family name (i.e., the same string in the second column)

The ground truth can be obtained from publicly available malware datasets. 
The one in *../examples/malheurReference_gt.tsv* comes from the 
[Malheur](http://www.mlsec.org/malheur/) dataset. 
There are other public datasets with ground truth such as 
[Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/) or 
[Malicia](http://malicia-project.com/dataset.html).

## Update Module

The update module can be used to suggest additions and changes to the input 
taxonomy, tagging rules, and expansion rules. 
Using the update module comprises of two steps.
The first step is obtaining an alias file from the labeler:

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json -aliasdetect
```

The above command will create a file named \<file\>.alias, 
malheurReference_lb.alias in our example. This file has 7 columns:

1. t1: token that is an alias
2. t2: tag for which t1 is an alias
3. |t1|: number of input samples where t1 was observed
4. |t2|: number of input samples where t2 was observed
5. |t1^t2|: number of input samples where both t1 and t2 were observed
6. |t1^t2|/|t1|: ratio of input samples where both t1 and t2 were observed over the number of input samples where t1 was observed.
7. |t1^t2|/|t2|: ratio of input samples where both t1 and t2 were observed over the number of input samples where t2 was observed.


The Update Module takes the above file as input with the -alias option, 
as well as the default taxonomy, tagging, and expansion files in the data directory. 
It outputs updated taxonomy, tagging, and expansion files that include the 
suggested additions and changes. 

```shell
$./avclass2_update_module.py -alias malheurReference_lb.alias -o output_prefix
```

This will produce three files: 
output_prefix.taxonomy, output_prefix.tagging, output_prefix.expansion. 
You can diff the output and input files to analyze the proposed changes.

You can also modify the input taxonomy, tagging, and expansion rules in place, 
rather than producing new files:


```shell
$./avclass2_update_module.py -alias malheurReference_lb.alias -update
```


## Customizing AVClass2

AVClass2 is fully customizable: 
Tagging, Expansion and Taxonomy files can be easily modified by the analyst 
either manually or by running the update module. 

If you change those files manually, we recommend running 
afterwards the input checker script to keep them tidy. 
It sorts the tags in the taxonomy and performs some basic cleaning like 
removing redundant entries:

```shell
$./avclass2_input_checker.py -tax taxonomy_file -tag tagging_file -exp expansio_file
```

If the modifications are in the default files in the data directory you can simply run: 

```shell
$./avclass2_input_checker.py 
```
