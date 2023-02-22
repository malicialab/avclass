import os

AVCLASS_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDER = os.path.join(AVCLASS_ROOT, 'data/')

RESOURCE_TAG = "default.tagging"
RESOURCE_TAX = "default.taxonomy"
RESOURCE_EXP = "default.expansion"

DEFAULT_TAX_PATH = os.path.join(DATA_FOLDER, RESOURCE_TAX)
DEFAULT_TAG_PATH = os.path.join(DATA_FOLDER, RESOURCE_TAG)
DEFAULT_EXP_PATH = os.path.join(DATA_FOLDER, RESOURCE_EXP)

