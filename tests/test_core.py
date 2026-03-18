"""Tests for Vulnfix."""
from src.core import Vulnfix
def test_init(): assert Vulnfix().get_stats()["ops"] == 0
def test_op(): c = Vulnfix(); c.detect(x=1); assert c.get_stats()["ops"] == 1
def test_multi(): c = Vulnfix(); [c.detect() for _ in range(5)]; assert c.get_stats()["ops"] == 5
def test_reset(): c = Vulnfix(); c.detect(); c.reset(); assert c.get_stats()["ops"] == 0
def test_service_name(): c = Vulnfix(); r = c.detect(); assert r["service"] == "vulnfix"
