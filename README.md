# AVClass
AVClass is a Python package / command line tool to tag / label malware samples. 
You input the AV labels for a large number of malware samples (e.g., VirusTotal JSON reports) 
and it outputs tags extracted from the AV labels of each sample. 
AVClass will output the family names, along with other tags capturing the malware class (e.g., *worm*, *ransomware*, *grayware*), behaviors (e.g., *spam*, *ddos*), and file properties (e.g., *packed*, *themida*, *bundle*, *nsis*).  It can also output a ranking of all alternative family names it found for each sample.
There is also a compatibility mode `-c` (AVClass 1.x) that will only output the family names (i.e., family tags). 

## Install
```shell
$ git clone http://.../avclass
$ cd avclass
$ pip3 install .
```

## Examples
A quick example helps illustrating the differences of 1.x compatibility mode. If you run AVClass on our example input file:

```shell
$ avclass -i ./examples/malheurReference_lb.json -t lb -p
```

the output on stdout is:

```
aca2d12934935b070df8f50e06a20539 33 CLASS:grayware|10,CLASS:grayware:adware|9,FILE:os:windows|8,FAM:adrotator|8,CLASS:downloader|3,FAM:zlob|2
67d15459e1f85898851148511c86d88d 37 CLASS:dialer|23,FILE:os:windows|9,FAM:adultbrowser|8,CLASS:dialer:porndialer|7,CLASS:grayware|6,CLASS:grayware:tool|3,FAM:target|2
```
which means sample *aca2d12934935b070df8f50e06a20539* 
was flagged by 33 AV engines and 10 of them agree it is *grayware*, 9 that it is more specifically *adware*, 
8 mention that it runs on *windows*, another 8 that it is the *adrotator* family, 
3 that it is a *downloader*, and 2 that it belongs instead to the *zlob* family.
Sample *67d15459e1f85898851148511c86d88d* is flagged by 37 AV engines and 23 of them 
consider it a *dialer*, 8 that it belongs to the *adultbrowser* family, and so on.

If you instead run AVClass on the same input file in compatibility mode `-c`:

```shell
$ avclass -i ./examples/malheurReference_lb.json -t lb -c
```

the output looks like this, which simply reports the most common family name for each sample.

```
aca2d12934935b070df8f50e06a20539 adrotator
67d15459e1f85898851148511c86d88d adultbrowser
``` 


The output can also be formatted as **JSON**.
```shell
$ avclass -i ./examples/malheurReference_lb.json -t lb -p -json
```
the output on stdout is:

```yaml
{
  "labels": [
    {
      "hash": "aca2d12934935b070df8f50e06a20539",
      "av_count": 33,
      "tags": [
        {
          "tag": "grayware",
          "count": 9,
          "category": "CLASS",
          "path": "CLASS:grayware"
        },
        {
          "tag": "adware",
          "count": 9,
          "category": "CLASS",
          "path": "CLASS:grayware:adware"
        },
        {
          "tag": "windows",
          "count": 8,
          "category": "FILE",
          "path": "FILE:os:windows"
        },
        {
          "tag": "adrotator",
          "count": 8,
          "category": "FAM",
          "path": "FAM:adrotator"
        },
        {
          "tag": "execdownload",
          "count": 3,
          "category": "BEH",
          "path": "BEH:execdownload"
        },
        {
          "tag": "downloader",
          "count": 3,
          "category": "CLASS",
          "path": "CLASS:downloader"
        },
        {
          "tag": "zlob",
          "count": 2,
          "category": "FAM",
          "path": "FAM:zlob"
        }
      ]
    }
  ]
}
```

Or it can be used as a Python package:
```py
import json
from avclass.labeler import AVClassLabeler

av_class = AVClassLabeler()
result = av_class.run(
    files="./examples/malheurReference_lb.json",
    data_type="lb",
    path_export=True,
)
print(json.dumps(result))
```
## Labeling: Ground Truth Evaluation

If you have family ground truth for some malware samples, i.e., 
you know the true family for those samples, you can evaluate the accuracy 
of the family tags output by AVClass2 on those samples with respect to that ground truth. 
The evaluation metrics used are precision, recall, and F1 measure. 
See our [RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf) for their definition.
Note that the ground truth evaluation does not apply to non-family tags, 
i.e., it only evaluates the output of the compatibility mode.

```shell
$ avclass -i ./examples/malheurReference_lb.json -t lb -gt ./examples/malheurReference_gt.tsv > malheurReference.labels
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
$ avclass -i ./examples/malheurReference_lb.json -t lb -aliasdetect
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
$ avclass-update -alias malheurReference_lb.alias -o output_prefix
```

This will produce three files: 
output_prefix.taxonomy, output_prefix.tagging, output_prefix.expansion. 
You can diff the output and input files to analyze the proposed changes.

You can also modify the input taxonomy, tagging, and expansion rules in place, 
rather than producing new files:


```shell
$ avclass-update -alias malheurReference_lb.alias -update
```


## Customizing AVClass

AVClass is fully customizable: 
Tagging, Expansion and Taxonomy files can be easily modified by the analyst 
either manually or by running the update module. 

If you change those files manually, we recommend running 
afterwards the input checker script to keep them tidy. 
It sorts the tags in the taxonomy and performs some basic cleaning like 
removing redundant entries:

```shell
$ avclass-validate -tax taxonomy_file -tag tagging_file -exp expansio_file
```

If the modifications are in the default files in the data directory you can simply run: 

```shell
$ avclass-validate
```

## References

The design and evaluation of AVClass is detailed in our 
[RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf):

> Marcos Sebastián, Richard Rivera, Platon Kotzias, and Juan Caballero. 
AVClass: A Tool for Massive Malware Labeling. 
In Proceedings of the International Symposium on Research in 
Attacks, Intrusions and Defenses,
September 2016.

The design and evaluation of AVClass2 is detailed in our
[ACSAC 2020 paper](https://arxiv.org/pdf/2006.10615.pdf):

> Silvia Sebastián, Juan Caballero. 
AVClass2: Massive Malware Tag Extraction from AV Labels. 
In proceedings of the Annual Computer Security Applications Conference, December 2020.

## Why is AVClass useful?

Because a lot of times security researchers want to extract family and other 
information from AV labels, but this process is not as simple as it looks, 
especially if you need to do it for large numbers (e.g., millions) of samples. 
Some advantages of AVClass are:

1. *Automatic.* They remove manual analysis limitations on the size of the 
input dataset.

2. *Vendor-agnostic.* They operate on the labels of any available set of AV 
engines, which can vary from sample to sample.

3. *Cross-platform.* They can be used for any platforms supported by AV 
engines, e.g., Windows or Android malware.

4. *Does not require executables.* AV labels can be obtained from online services
 like VirusTotal using a sample's hash, even when the executable is not available.

5. *Quantified accuracy.* We have evaluated AVClass 2.x on millions of 
samples and publicly available malware datasets with ground truth. 
Evaluation details are in the RAID 2016 and ACSAC 2020 papers.

6. *Open source.* The code is available and we are happy to incorporate 
suggestions and improvements so that the security community benefits from 
these tools.

## Limitations

The main limitations of AVClass is that the output depends 
on the input AV labels. 
The tool tries to compensate for the noise on the AV labels, 
but cannot identify tags if AV engines do not provide non-generic tokens 
in the labels of a sample. 
In particular, it cannot tag samples if at least 2 AV engines 
do not agree on a tag. 

Still, there are many samples that it can tag
and thus we believe you will find it useful.
We recommend you to read the RAID 2016 and ACSAC 2020 papers for more details.

## Input JSON format

AVClass supports four input JSON formats: 

1. VirusTotal v2 API JSON reports (*-vt file*), 
where each line in the input *file* should be the full JSON of a 
VirusTotal v2 API response to the */file/report* endpoint,
e.g., obtained by querying https://www.virustotal.com/vtapi/v2/file/report?apikey={apikey}&resource={hash}
There is an example VirusTotal v2 input file in examples/vtv2_sample.json

```shell
$ avclass -i examples/vtv2_sample.json -t vt2 -p > output.txt
```

2. VirusTotal v3 API JSON reports (*-vt file -vt3*), 
where each line in the input *file* should be the full JSON of a VirusTotal API version 3 response with a *File* object report, 
e.g., obtained by querying https://www.virustotal.com/api/v3/files/{hash}
There is an example VirusTotal v3 input file in examples/vtv3_sample.json

```shell
$ avclass -i examples/vtv3_sample.json -p -t vt3 > output.txt
```

3. Simplified JSON (*-lb file*),
where each line in *file* should be a JSON 
with (at least) these fields:
{md5, sha1, sha256, av_labels}. 
There is an example of such input file in *examples/malheurReference_lb.json*

```shell
$ avclass -i examples/malheurReference_lb.json -t lb -p > output.txt
```

4. Metadefender JSON (*-md file*),
where each line in *file* should be a JSON

```shell
$ avclass -i examples/malheurReference_lb.json -t md -p > output.txt
```

**Why have a simplified JSON format?**

We believe most users will get the AV labels using VirusTotal. 
However, AVClass is IO-bound and a VirusTotal report 
in addition to the AV labels and hashes includes 
a lot of other data that the tools do not need. 
Thus, when applying AVClass to millions of samples,
reducing the input file size by removing unnnecessary data 
significantly improves efficiency. 
Furthermore, users could obtain AV labels from other sources and 
the simpler the input JSON format, 
the easier to convert those AV labels into an input file.

## Dependencies

AVClass is both written in Python. 
It should be run on Python versions >= 3.6.

They do not require installing any dependencies.

## Support and Contributing

If you have issues or want to contribute, please file a issue or perform a 
pull request through GitHub.

## License

AVClass is released under the MIT license

## Contributors

Several members of the MaliciaLab at the [IMDEA Software Institute](http://software.imdea.org) 
have contributed code to AVClass: 
Marcos Sebastián, Richard Rivera, Platon Kotzias, Srdjan Matic, Silvia Sebastián, and Juan Caballero.

