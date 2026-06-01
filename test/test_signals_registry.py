# test/test_signals_registry.py
from mpierce.signals import Detector, get_detectors


def test_registry_returns_named_detectors():
    detectors = get_detectors()
    names = {d.name for d in detectors}
    assert names == {"status", "content", "explicit", "timing"}


def test_detectors_conform_to_protocol():
    for d in get_detectors():
        assert isinstance(d.name, str)
        assert callable(d.detect)
