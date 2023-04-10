# AVClass

AVClass is a Python package and command line tool to tag / label
malware samples.
You input the AV labels for a large number of malware samples
(e.g., VirusTotal JSON reports)
and it outputs a list of tags extracted from the AV labels of each sample.

By default, AVClass outputs the most likely family name for each sample,
but it can also output other tags that capture
the malware class (e.g., *worm*, *ransomware*, *grayware*),
behaviors (e.g., *spam*, *ddos*), and
file properties (e.g., *packed*, *themida*, *bundle*, *nsis*).

If you are wondering if this is AVClass or AVClass2,
the answer is this is the right place for both.
The old AVClass code has been deprecated and
AVClass2 has been renamed as AVClass.
A longer explanation is below.

## Installation
```shell
pip install avclass-malicialab
```

## Examples

To obtain the most likely family name for each sample, run:

```shell
avclass -f examples/vtv2_sample.json
```

the output on stdout will be:

```
602695c8f2ad76564bddcaf47b76edff  zeroaccess
f117cc1477513cb181cc2e9fcaab39b2  winwebsec
```

which simply reports the most common family name for each sample.

For some samples, AVClass may return:

```
5e31d16d6bf35ea117d6d2c4d42ea879	SINGLETON:5e31d16d6bf35ea117d6d2c4d42ea879
```

This means that AVClass was not able to identify a family name for that sample.
AVClass uses the SINGLETON:hash terminology,
(e.g., instead of an empty string or NULL)
so that the second column can be used as a cluster identifier where
each unlabeled sample is placed in its own cluster.
This prevents considering that all unlabeled samples are part of the
same family / cluster.

To extract all tags for each sample run:

```shell
avclass -f examples/vtv2_sample.json -t
```

the output on stdout will be:

```
602695c8f2ad76564bddcaf47b76edff  52  FAM:zeroaccess|19,FILE:os:windows|16,BEH:server|8,CLASS:backdoor|8,FILE:packed|7
f117cc1477513cb181cc2e9fcaab39b2  39  CLASS:rogueware|15,BEH:alertuser|15,FILE:os:windows|11,FAM:winwebsec|4,CLASS:grayware|4,CLASS:grayware:tool|3,FILE:packed|3
```
which means sample *602695c8f2ad76564bddcaf47b76edff*
was flagged by 52 AV engines and that
19 of them mention it belongs to the *zeroaccess* family,
16 that it runs on *windows*,
8 that it is a *backdoor*, and
7 that it is a *packed* file.
Sample *f117cc1477513cb181cc2e9fcaab39b2* is flagged by 39 AV engines and
15 of them mention its class to be *rogueware*,
15 that it has the *alertuser* behavior,
11 that it runs on *windows*,
4 that it belongs to the *winwebsec* family,
and so on.

You can also place the output in a file of your choosing with the _-o_ option:

```shell
avclass -f examples/vtv2_sample.json -o output.txt
```

## Why is AVClass useful?

Because a lot of times security researchers want to extract family and other
information from AV labels, but this process is not as simple as it looks,
especially if you need to do it for large numbers (e.g., millions) of samples.
Some advantages of AVClass are:

1. *Automatic.* It avoids manual work that does not scale for large datasets.

2. *Vendor-agnostic.* It operates on the labels of any available set of AV
engines, which can vary from sample to sample.

3. *Cross-platform.* It can be used for any platforms supported by AV
engines, e.g., Windows or Android malware.

4. *Does not require executables.* AV labels can be obtained from online
services like VirusTotal using a sample's hash,
even when the executable is not available.

5. *Quantified accuracy.* We have evaluated AVClass on millions of
samples and publicly available malware datasets with ground truth.
Evaluation details are in the RAID 2016 and ACSAC 2020 papers
(see References section).

6. *Open source.* The code is available and we are happy to incorporate
suggestions and improvements so that the security community benefits from
the tool.

## Limitations

The main limitations of AVClass is that its output depends
on the input AV labels.
AVClass tries to compensate for the noise on the AV labels,
but it cannot identify tags if AV engines do not provide non-generic tokens
in the labels of a sample.
In particular, it only outputs tags that appear in the labels of
at least 2 AV engines.

Still, there are many samples that can be tagged
and thus we believe you will find it useful.

## Is this AVClass or AVClass2?

The short answer is that the current code in this repo is
based on the code of AVClass2.
The original AVClass code has been deprecated.
Below, we detail this process.

We originally published AVClass in RAID 2016 and made its code
available in this repository in July 2016.
AVClass extracted only the family names from the input samples.

We published AVClass2 in ACSAC 2020 and made its code
available in this repository in September 2020.
AVClass2 extracted all tags from the input samples and included a
compatibility option to provide only the family names in the
same format as the original AVClass.

For 2.5 years, both tools were available in this repository in
separate directories.
In February 2023, we decided to 
deprecate the original AVClass code,
rename AVClass2 as AVClass, 
release a PyPI package to ease installation, and 
clean the command line options.

## Input formats

AVClass supports four input JSONL formats
(i.e., one JSON object per line).

1. VirusTotal v3 API reports,
where each line in the input *file* should be the full JSON of a
VirusTotal API version 3 response with a *File* object report,
e.g., obtained by querying https://www.virustotal.com/api/v3/files/{hash}
There is an example VirusTotal v3 input file in examples/vtv3_sample.json

```shell
avclass -f examples/vtv3_sample.json -o output.txt
```

2. VirusTotal v2 API reports,
where each line in the input *file* should be the full JSON of a
VirusTotal v2 API response to the */file/report* endpoint,
e.g., obtained by querying https://www.virustotal.com/vtapi/v2/file/report?apikey={apikey}&resource={hash}
There is an example VirusTotal v2 input file in examples/vtv2_sample.json

```shell
avclass -f examples/vtv2_sample.json -o output.txt
```

3. OPSWAT MetaDefender reports,
where each line in the input *file* should be the full JSON
obtained from OPSWAT MetaDefender.
There is an example OPSWAT MetaDefender input file in
examples/opswat_md_sample.json

```shell
avclass -f examples/opswat_md_sample.json -o output.txt
```

4. Simplified format,
where each line in the input *file* should be a JSON
with (at least) these fields:
{md5, sha1, sha256, av_labels}.
There is an example of such input file in *examples/malheurReference_lb.json*
If you are obtaining AV labels from sources other than VirusTotal you 
may want to convert them to this format.

```shell
avclass -f examples/malheurReference_lb.json -o output.txt
```

**Multiple input files and different formats**

AVClass can handle multiple input files putting the results in the
same output files
(if you want results in separate files, process each input file separately).
AVClass automatically detects the format of each file, 
so it is possible to mix input files.

For example, you can provide as input the three test files
(each of a different format) in the examples directory:

```shell
avclass -f examples/vtv3_sample.json -f examples/vtv2_sample.json -f examples/malheurReference_lb.json -f examples/opswat_md_sample.json -o output.txt
```

output.txt will have 3135 lines: 3130 samples from malheurReference_lb.json,
3 samples from vtv2_sample.json, 1 sample from vtv3_sample.json, and
1 sample from opswat_md_sample.json.

You can also provide as input a directory with the -d option and 
AVClass will process all files in that directory. 

```shell
avclass -d <directory>
```

It is also possible to combine -f with -d,
Thus, this command works:

```shell
avclass -f <file> -d <directory>
```

At this point you have read the most important information on
how to use AVClass.
The following sections describe steps that most users will not need.

## Labeling: Using only Selected AV Engines

By default, AVClass will use the labels of all AV engines that appear in
the input reports.
If you want to limit AVClass to use only the labels of certain AV engines,
you can use the -av option to pass it a file where each line has the name of
an AV engine (case-sensitive).

For example, you could create a file engines.txt with three lines:
BitDefender
F-Secure
Sophos

```shell
avclass -av engines.txt -f examples/vtv2_sample.json -t -o output.txt
```

would output into output.txt:
```
602695c8f2ad76564bddcaf47b76edff  3 FAM:zeroaccess|2
f117cc1477513cb181cc2e9fcaab39b2  3
```

where only the labels of BitDefender, F-Secure, and Sophos have been used
to extract tags.
The output states all three selected engines flag both samples as malicious.
Note that the number of detections is with respect to the provided engines,
i.e., even if the first sample has 52 detections,
the number of detections is a maximum of 3 in this case.
For the first sample, two AV engines identify the family as *zeroaccess* but
for the second sample no tags are identified in the labels
of the three selected AV engines.

## Labeling: Ground Truth Evaluation

If you have family ground truth for some malware samples,
i.e., you know the true family for those samples,
you can evaluate the accuracy of the family tags output by AVClass on
those samples with respect to that ground truth.
The evaluation metrics used are precision, recall, and F1 measure.
See our
[RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf) for their definition.
Note that the ground truth evaluation does not apply to non-family tags,
i.e., it only evaluates family labeling.

```shell
avclass -f examples/malheurReference_lb.json -gt examples/malheurReference_gt.tsv -o malheurReference.labels
```

The output includes these lines:

```
Calculating precision and recall
3131 out of 3131
Precision: 90.81  Recall: 93.95 F1-Measure: 92.35
```

Each line in the *examples/malheurReference_gt.tsv* file has
three **tab-separated** columns (hash, AVClass family, GT family):

```
afdd8f086dfcb8d2cf26c566e784476dd899ec10 adrotator ADROTATOR
```

which indicates that sample afdd8f086dfcb8d2cf26c566e784476dd899ec10 
is identified as *adrotator* by AVClass and 
its ground truth family is *ADROTATOR*.
Each sample in the input file should also appear in the ground truth file.
Note that the particular label assigned to each family does not matter.
What matters is that all samples in the same family are assigned
the same family name (i.e., the same string in the second column)

The ground truth can be obtained from publicly available malware datasets.
The one in *examples/malheurReference_gt.tsv* comes from the
[Malheur](http://www.mlsec.org/malheur/) dataset.
There are other public datasets with ground truth such as
[Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/) or
[Malicia](http://malicia-project.com/dataset.html).


## Update Module

The update module can be used to suggest additions and changes to the input
taxonomy, tagging rules, and expansion rules.
By default, AVClass uses the default taxonomy, tagging, and expansion files
included in the repository.
Thus, we expect that most users will not need to run the update module.
But, below we explain how to run in case you need to.

Using the update module comprises of two steps.
The first step is obtaining an alias file:

```shell
avclass -f examples/malheurReference_lb.json -aliasdetect -o /dev/null
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
as well as the default taxonomy, tagging, and expansion files
in the data directory.
It outputs updated taxonomy, tagging, and expansion files that include the
suggested additions and changes.

```shell
avclass-update -alias malheurReference_lb.alias -o output_prefix
```

This will produce three files:
output_prefix.taxonomy, output_prefix.tagging, output_prefix.expansion.
You can diff the output and input files to analyze the proposed changes.

You can also modify the input taxonomy, tagging, and expansion rules in place,
rather than producing new files:

```shell
avclass-update -alias malheurReference_lb.alias -update
```

## Customizing AVClass

AVClass is fully customizable:
Tagging, Expansion and Taxonomy files can be easily modified by the analyst
either manually or by running the update module.

If you change those files manually, we recommend running
afterwards the normalization script to keep them tidy.
It sorts the tags in the taxonomy and performs some basic cleaning like
removing redundant entries:

```shell
avclass-normalize -tax mytaxonomy -tag mytagging -exp myexpansions
```

If the modifications are in the default files in the data directory you can
simply run:

```shell
avclass-normalize
```

## Evaluating and comparing with AVClass

Other researchers may want to independently evaluate AVClass/AVClass2 and
to compare it with their own approaches.
We encourage such evaluation, feedback on limitations, and proposals for
improvement.
However, we have observed a number of common errors in such evaluations that
should be avoided.
Thus, if you need to compare your approach with AVClass/AVClass2,
please read the [evaluation page](EVALUATION.md)

## Dependencies

AVClass is written in Python.
It should run on Python versions above 2.7 and 3.0.

It does not require installing any dependencies.

## Support and Contributing

If you have issues or want to contribute, please file a issue or perform a
pull request through GitHub.

## License

AVClass is released under the MIT license

## References

The design and evaluation of AVClass is detailed in our
[RAID 2016 paper](https://software.imdea.org/~juanca/papers/avclass_raid16.pdf):

> Marcos Sebastián, Richard Rivera, Platon Kotzias, and Juan Caballero.<br>
AVClass: A Tool for Massive Malware Labeling.<br>
In Proceedings of the International Symposium on Research in
Attacks, Intrusions and Defenses,
September 2016.

The design and evaluation of AVClass2 is detailed in our
[ACSAC 2020 paper](https://arxiv.org/pdf/2006.10615.pdf):

> Silvia Sebastián, Juan Caballero.<br>
AVClass2: Massive Malware Tag Extraction from AV Labels.<br>
In proceedings of the Annual Computer Security Applications Conference,
December 2020.

## Contributors

Several members of the MaliciaLab at the
[IMDEA Software Institute](http://software.imdea.org)
have contributed to AVClass:
Marcos Sebastián, Richard Rivera, Platon Kotzias, Srdjan Matic,
Silvia Sebastián, Kevin van Liebergen, and Juan Caballero.

GitHub users with significant contributions to AVClass include
(let us know if you believe you should be listed here):
[eljeffeg](https://github.com/eljeffeg)

