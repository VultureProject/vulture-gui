from .harfanglab import HarfangLabCollector
from .proofpoint_trap import ProofpointTRAPCollector

MODELS_LIST = {
    "harfanglab": HarfangLabCollector,
    "proofpoint_trap": ProofpointTRAPCollector,
}