# AVClass and AVClass2

AVClass and AVClass2 are Python tools to tag / label malware samples. 
You give them as input the AV labels for a large number of malware samples (e.g., VirusTotal JSON reports) 
and they output tags extracted from the AV labels of each sample. 
The original AVClass only outputs family names (i.e., family tags). 
By default, it outputs the most likely family for each sample (e.g., *zbot*, *virut*). 
It can also output a ranking of all alternative family names it found for each sample.
The newer AVClass2, in addition to family names, also outputs other tags capturing the malware class (e.g., *worm*, *ransomware*, *grayware*), behaviors (e.g., *spam*, *ddos*), and file properties (e.g., *packed*, *themida*, *bundle*, *nsis*). 

A quick example helps illustrating the differences. If you run AVClass2 on our example input file:

```shell
$./avclass2/avclass2_labeler.py -lb examples/malheurReference_lb.json -p
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

If you instead run AVClass on the same input file:

```shell
$./avclass/avclass_labeler.py -lb examples/malheurReference_lb.json
```

the output looks like this:

```
aca2d12934935b070df8f50e06a20539 adrotator
67d15459e1f85898851148511c86d88d adultbrowser
``` 

which simply reports the most common family name for each sample.

In a nutshell, that is the main difference between both tools. 
Of course, there are more options for both tools, 
which you can read about in their corresponding README files. 


## Which one should I use?

AVClass2 is the newer tool and it extracts more information 
from the input AV labels.
So, if you are new to AVClass and AVClass2, we recommend trying it out first.

However, there are several reasons to keep AVClass around. 
First, it is more mature and used by many analysts, 
so we want to preserve backwards compatibility.
Second, for some applications only family names are needed and 
for that AVClass is enough.
Third, AVClass is faster than AVClass2 since it extracts less info. 
The lower runtime is nice when processing millions of samples and 
not requiring the extra tags AVClass2 provides. 

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

## Why are AVClass and AVClass2 useful?

Because a lot of times security researchers want to extract family and other 
information from AV labels, but this process is not as simple as it looks, 
especially if you need to do it for large numbers (e.g., millions) of samples. 
Some advantages of AVClass and AVClass2 are:

1. *Automatic.* They remove manual analysis limitations on the size of the 
input 
dataset.

2. *Vendor-agnostic.* They operate on the labels of any available set of AV 
engines, which can vary from sample to sample.

3. *Cross-platform.* They can be used for any platforms supported by AV 
engines, e.g., Windows or Android malware.

4. *Does not require executables.* AV labels can be obtained from online services
 like VirusTotal using a sample's hash, even when the executable is not available.

5. *Quantified accuracy.* We have evaluated AVClass and AVClass2 on millions of 
samples and publicly available malware datasets with ground truth. 
Evaluation details are in the RAID 2016 and ACSAC 2020 papers.

6. *Open source.* The code is available and we are happy to incorporate 
suggestions and improvements so that the security community benefits from 
these tools.

## Limitations

The main limitations of AVClass and AVClass2 are that its output depends 
on the input AV labels. 
Both tools try to compensate for the noise on the AV labels, 
but cannot identify tags if AV engines do not provide non-generic tokens 
in the labels of a sample. 
In particular, they cannot tag samples if at least 2 AV engines 
do not agree on a tag. 

Still, there are many samples that both tools can tag
and thus we believe you will find them useful.
We recommend you to read the RAID 2016 and ACSAC 2020 papers for more details.

## Input JSON format

AVClass and AVClass2 support three input JSON formats: 

1. VirusTotal v2 API JSON reports (*-vt file*), 
where each line in the input *file* should be the full JSON of a 
VirusTotal v2 API response to the */file/report* endpoint,
e.g., obtained by querying https://www.virustotal.com/vtapi/v2/file/report?apikey={apikey}&resource={hash}
There is an example VirusTotal v2 input file in examples/vtv2_sample.json

```shell
$./avclass2/avclass2_labeler.py -vt examples/vtv2_sample.json -p > output.txt
```

2. VirusTotal v3 API JSON reports (*-vt file -vt3*), 
where each line in the input *file* should be the full JSON of a VirusTotal API version 3 response with a *File* object report, 
e.g., obtained by querying https://www.virustotal.com/api/v3/files/{hash}
There is an example VirusTotal v3 input file in examples/vtv3_sample.json

```shell
$./avclass2/avclass2_labeler.py -vt examples/vtv3_sample.json -p -vt3 > output.txt
```

3. Simplified JSON (*-lb file*),
where each line in *file* should be a JSON 
with (at least) these fields:
{md5, sha1, sha256, av_labels}. 
There is an example of such input file in *examples/malheurReference_lb.json*

```shell
$./avclass2/avclass2_labeler.py -lb examples/malheurReference_lb.json -p > output.txt
```

**Why have a simplified JSON format?**

We believe most users will get the AV labels using VirusTotal. 
However, AVClass and AVClass2 are IO-bound and a VirusTotal report 
in addition to the AV labels and hashes includes 
much other data that the tools do not need. 
Thus, when applying AVClass or AVClass2 to millions of samples,
reducing the input file size by removing unnnecessary data 
significantly improves efficiency. 
Furthermore, users could obtain AV labels from other sources and 
the simpler the input JSON format, 
the easier to convert those AV labels into an input file.

## Dependencies

AVClass and AVClass2 are both written in Python. 
They should both run on Python versions above 2.7 and 3.0.

They do not require installing any dependencies.

## Support and Contributing

If you have issues or want to contribute, please file a issue or perform a 
pull request through GitHub.

## License

AVClass and AVClass2 are both released under the MIT license

## Contributors

Several members of the MaliciaLab at the [IMDEA Software Institute](http://software.imdea.org) 
have contributed code to AVClasss and AVClass2: 
Marcos Sebastián, Richard Rivera, Platon Kotzias, Srdjan Matic, Silvia Sebastián, and Juan Caballero.

