# Evaluating and Comparing with AVClass2 / AVClass

Other researchers may want to independently evaluate AVClass/AVClass2 and 
to compare it with their own approaches. 
We encourage such evaluation, feedback on limitations, and proposals for 
improvement.
However, we have observed a number of works that 
evaluate AVClass/AVClass2, and compare them with their own approaches,
in ways we deem incorrect. 
This page is a work in progress to explain common errors that we 
have observed, so that they can be avoided.
We'll try to update this page as we observe new issues.

Here is the quick summary if you are in a hurry:

1. AVClass2 has superseeded AVClass, so your evaluation should include AVClass2, not only the original AVClass.
2. For malware labeling, please use AVClass2 compatibility mode (-c command line option).
3. Tagging more samples is not an evaluation goal by itself, the tags need to be accurate. For example, it is known that allowing tags from a single AV engine or ignoring generic tags will enable tagging more samples, but it will introduce incorrect tags.
4. You need ground truth to evaluate the accuracy/precision/recall of AVClass/AVClass2.
5. You should also evaluate scalability (runtime and memory usage) since that is a major design goal of AVClass/AVClass2
6. Note that AVClass2 and AVClass may not provide the same family tag for all samples when run on the same AV labels.
7. AVClass2/AVClass are not malware detection tools, please do not try to evaluate them for that scenario.

## Which tool should I evaluate and compare with?

You should evaluate and compare with AVClass2. 
It is the newer tool, extracts more information 
from the input AV labels, and has a compatibility mode to be used for 
family labeling in the same way that the original AVClass. 

It is fine to include the original AVClass in your evaluation, 
but you should include AVClass2 as well. 
The original AVClass is from 2016 and was superseeded in 2020 by 
AVClass2. Evaluating only on the older tool could be seen as unfair. 

## How do I evaluate AVClass2 for malware family labeling?

Oftentimes, researchers only want to evaluate AVClass/AVClass2 for 
malware family labeling, i.e., for assigning a family name to samples. 

A common error is to use AVClass2 without the compatibility mode
(-c command line option). 
A key design idea in AVClass and AVClass2 is that tags not known a 
priori (e.g., new tags added by AV engines) are likely family names. 
When using the compatibility mode, AVClass2 selects as likely family for 
the sample the highest known family (FAM) or unknown tag (UNK) for the sample.
This makes AVClass2 behave similarly to the original AVClass for 
malware family labeling.

Without the compatibility mode, you instead get all tags for the sample.
Many tags are not related to family labeling 
(e.g., CLASS, BEH, FILE tag prefixes do not capture families).
If you simply keep the top tag for the sample, you'll likely keep a 
FILE:windows or FILE:android tag that is unrelated to the sample's family.
Alternatively, you could think of selecting only the highest 
ranked family (FAM) tag, but this is incorrect as well because you 
would be ignoring the unknown (UNK) tags. 
This will lead to underestimating the number of samples AVClass2 can 
correctly label, thus underestimating its accuracy and recall.

For malware family labeling, you should use the compatibility mode of AVClass2 
by passing the -c command line option. 
This generates an output in the same format as the original AVClass.

```shell
$./avclass2_labeler.py -lb ../examples/malheurReference_lb.json -c
```

## Do I need ground truth to evaluate the tools?

Yes, you do. Note that the goal of AVClass/AVClass2 is not to 
tag as many samples as possible.
The output tags need be **accurate**, especially for family tags.
Thus, the quality of the tags assigned to samples should be evaluated.

Some common mistakes in malware family labeling are ignoring generic tags 
and assigning class/behavior/file tags as if they are families. 
For example, if a paper was to use a *trojandownloader* family 
that would inspire little confidence in their results. 

There are several design decisions in AVClass/AVClass2 that purposefully 
reduce the number of tagged samples in order to minimize incorrect tags. 
Some worth mentioning are: 
avoiding to consider CLASS/BEH/FILE tags as family names, 
removing generic tags such as *malicious* that do not provide real info, 
taking into account groups of AV engines that copy their labels 
(e.g., different engines from the same vendor), and
requiring at least two AV engines to assign the same tag to the sample. 

It is simple to modify AVClass/AVClass2 to remove some of those requirements
(e.g., to allow tags from a single AV engine or to not account for clusters 
of AV engines). 
It is known that such changes will increase the amount of tagged samples, 
so proposing such changes does not really provide novelty. 
The problem is that such changes will introduce noise in the output as well, 
which is precisely the reason those rules are there in the first place.

In most cases, when AVClass/AVClass2 cannot label samples is because there 
is no useful information in the AV labels, i.e., the labels are generic. 
This is not rare as many AV vendors have generic detection systems based on 
machine learning, heuristics, and behavioral information that may not identify 
a specific family, but general maliciousness.
On the other hand, if you find samples for which you believe there is 
useful information in the AV labels that AVClass2 is not extracting, 
feel free to open an issue. 

## AVClass/AVClass2 sucks because it only labels X\% of samples in my dataset

The goal is not necessarily to tag more, but to tag accurately.
Please read the above entry on ground truth. 

## Should I evaluate scalability as well?

Definitely. AVClass/AVClass2 are designed for massive labeling/tagging, 
i.e., to label/tag millions of samples. 
If you only evaluate the accuracy/precision/recall of the tools 
without considering their scalability (i.e., runtime and memory consumption) 
we feel that is an unfair evaluation. 
The reason for that is that many design choices in AVClass/AVClass2 
were taken in order to scale to very large numbers of samples.

Note that AVClass2 was evaluated on 42M scan reports and the original 
AVClass on 8.9M. 
Evaluating scalability typically requires several million scan reports. 
But, regardless of the size of your datasets, always evaluate scalability 
in the largest dataset you have, as there is no need for ground truth 
to evaluate the runtime and memory consumption.

## Do both tools output the same results for malware family labeling?

Not necessarily. 
Even if you use AVClas2 compatibility mode, its family labeling results may 
differ from the original AVClass family labels when run on the same AV labels. 
The main reason for this is the different generic and family aliases used 
by both tools. 
We no longer update those entries for the original AVClass tool and thus 
the discrepancies grow over time. 
In addition, there are small differences in other steps of the pipeline that 
will also change the results for some samples. 

In general, AVClass2 family labeling should outperform the original AVClass. 
That is why you should be using AVClass2 instead of the original AVClass.

## How do I evaluate AVClass/AVClass2 for malware detection?

You should not. AVClass/AVClass2 are malware labeling/tagging tools. 
You can evaluate both of them for malware clustering and 
for malware family labeling. 
You can also evaluate AVClass2 for malware tagging beyond family tags. 
But, malware detection is a binary (malicious versus benign) determination that 
they are not designed for. 

So please, do not to include AVClass/AVClass2 in your malware detection 
evaluation. 
There exist a myriad of malware detection tools you can compare with instead.
If you insist in evaluating AVClass/AVClass2 for malware detection, 
then please include a detailed explanation of how you turn a malware
labeling/tagging tool into a detection tool. 

