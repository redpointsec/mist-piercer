# mpierce/signals/__init__.py
from typing import Protocol, runtime_checkable

from ..models import Response, SignalVerdict


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        ...


def get_detectors() -> list[Detector]:
    """Return one instance of every registered signal detector."""
    from .status import StatusDetector
    from .content import ContentDetector
    from .explicit import ExplicitDetector
    from .timing import TimingDetector

    return [StatusDetector(), ContentDetector(), ExplicitDetector(), TimingDetector()]
