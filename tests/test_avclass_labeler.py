import pytest
import subprocess
import os


def call_with_output(array):
    p = subprocess.Popen(array, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    output, err = p.communicate()
    return output, err


def avclass_labeler_bin():
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, '../avclass_labeler.py')


def test_avclass_labeler_subprocess():
    params = ['python', avclass_labeler_bin(), '-lb', 'data/malheurReference_lb.json', '-v', '-fam']
    output, err = call_with_output(params)
    err = err.split('\n')
    assert err[-4].find('[-] Samples: 3131 NoLabels:') != -1, "err=%s" % err
