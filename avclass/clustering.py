import sys

from collections import defaultdict
from typing import Dict, Set


def tp_fp_fn(expected: Set, guess: Set):
    """
    Calculate the true-positives, false-positives, and false-negatives between ``expected`` and ``guess``

    :param expected: Ground truth set
    :param guess: Estimated set
    :return: Tuple containing true positive count, false positive count, false negative count
    """
    tp = len(guess.intersection(expected))
    fp = len(guess.difference(expected))
    fn = len(expected.difference(guess))

    return tp, fp, fn


def eval_precision_recall_fmeasure(expected: Dict, guess: Dict):
    """
    Evaluate the precision, recall, and f-measure for the comparison of ``expected`` to ``guess``

    :param expected: Dictionary mapping an element to a cluster_id
    :param guess: Dictionary mapping an element t a cluster_id
    :return: Tuple containing precision, recall, and f-measure values
    """
    # eval: precision, recall, f-measure
    tmp_precision = 0
    tmp_recall = 0

    # build reverse dictionary of guess
    rev_est_dict = defaultdict(set)
    for k, v in guess.items():
        rev_est_dict[v].add(k)

    # build reverse dictionary of expected
    gt_rev_dict = defaultdict(set)
    for k, v in expected.items():
        gt_rev_dict[v].add(k)

    counter, l = 0, len(guess)

    sys.stderr.write('Calculating precision and recall\n')

    # For each element
    for element in guess:
        # Print progress
        if counter % 1000 == 0:
            sys.stderr.write('\r%d out of %d' % (counter, l))
            sys.stderr.flush()
        counter += 1

        # Get elements in the same cluster (for "guess cluster")
        guess_cluster_id = guess[element]

        # Get the list of elements in the same cluster ("expected cluster")
        correct_cluster_id = expected[element]

        # Calculate TP, FP, FN
        tp, fp, fn = tp_fp_fn(gt_rev_dict[correct_cluster_id],
                              rev_est_dict[guess_cluster_id])

        # tmp_precision
        p = 1.0*tp/(tp+fp)
        tmp_precision += p

        # tmp_recall
        r = 1.0*tp/(tp+fn)
        tmp_recall += r

    sys.stderr.write('\r%d out of %d' % (counter, l))
    sys.stderr.write('\n')

    precision = 100.0 * tmp_precision / len(guess)
    recall = 100.0 * tmp_recall / len(guess)
    fmeasure = (2 * precision * recall) / (precision + recall)

    return precision, recall, fmeasure


if __name__ == "__main__":
    # The ground truth.
    # Dictionary with mapping: "element : cluster_id".
    diz_grth = {
        "a": 1,
        "b": 1,
        "c": 2,
        "d": 3
    }

    # An example of an "estimated cluster".
    # Dictionary with mapping: "element : cluster_id".
    diz_estim = {
        "a": 66,
        "b": 'malware',
        "c": 'goodware',
        "d": 'trojan'
    }

    # An example of an "estimated cluster": same partitioning as for the ground
    # truth, but just different cluster labels. Precision == Recall ==
    # F-Measure == 100%.
    # Dictionary with mapping: "element : cluster_id".
    diz_estim_grth = {
        "a": 2,
        "b": 2,
        "c": 66,
        "d": 9
    }

    # a sample where estimated != ground truth
    sys.stdout.write("Ground truth\n")
    sys.stdout.write("%8s --> %10s\n" % ("Element", "Cluster_ID"))

    for k, v in diz_grth.items():
        sys.stdout.write("%8s --> %10s\n" % (k, v))

    sys.stdout.write("\nEstimated clustering\n")
    sys.stdout.write("%8s --> %10s\n" % ("Element", "Cluster_ID"))

    for k, v in diz_estim.items():
        sys.stdout.write("%8s --> %10s\n" % (k, v))

    # precision, recall, f-measure
    p, r, f = eval_precision_recall_fmeasure(diz_grth, diz_estim)

    sys.stdout.write("\nPrecison: %s%%\n" % p)
    sys.stdout.write("Recall: %s%%\n" % r)
    sys.stdout.write("F-Measure: %s%%\n" % f)
