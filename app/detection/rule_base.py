"""Abstract interface for detection rules."""

from abc import ABC, abstractmethod

from typing import List

from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

class DetectionRule(ABC):
    """Base class that all detection rules must implement."""

    @abstractmethod
    def evaluate(
        self,
        events: List[NormalizedEvent],

    ) -> List["Alert"]:
        """Evaluate normalized events and return detected alerts."""
        raise NotImplementedError