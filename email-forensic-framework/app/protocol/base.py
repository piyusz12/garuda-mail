from abc import ABC, abstractmethod
from typing import List, Tuple

from app.models.session import ReconstructedSession
from app.models.protocol_event import ProtocolEvent, ProtocolDetection

class ProtocolAnalyzer(ABC):
    """Base interface for all application protocol analyzers"""
    
    @property
    @abstractmethod
    def protocol_name(self) -> str:
        pass
        
    @abstractmethod
    def detect(self, session: ReconstructedSession) -> ProtocolDetection:
        """
        Calculates confidence that the session matches this protocol based on payload inspection.
        Returns ProtocolDetection with score 0.0 to 1.0.
        """
        pass
        
    @abstractmethod
    def parse(self, session: ReconstructedSession) -> Tuple[List[ProtocolEvent], str]:
        """
        Parses the bidirectional stream and extracts protocol events.
        Returns a tuple of (events, parse_status) where status is COMPLETE, PARTIAL, or ERROR.
        """
        pass
