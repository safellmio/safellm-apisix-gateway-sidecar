"""Abstract base class for security layers."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(slots=True)
class ScanContext:
    """Context passed to each security layer."""
    text: str
    request_id: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass(slots=True)
class ScanResult:
    """Result from a security layer scan."""
    safe: bool
    score: float = 0.0
    reason: str = ""
    layer: str = ""
    latency_ms: float = 0.0
    
    @classmethod
    def ok(cls, layer: str = "") -> "ScanResult":
        """Factory for safe result."""
        return cls(safe=True, layer=layer)
    
    @classmethod
    def blocked(cls, reason: str, layer: str = "", score: float = 1.0) -> "ScanResult":
        """Factory for blocked result."""
        return cls(safe=False, reason=reason, layer=layer, score=score)


class SecurityLayer(ABC):
    """
    Abstract base class for all security layers.
    
    Each layer implements the scan() method which:
    - Returns ScanResult.ok() if content is safe
    - Returns ScanResult.blocked() if content should be blocked
    - Must be async to avoid blocking the event loop
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique layer identifier (e.g., 'L1_KEYWORDS', 'L2_AI')."""
        pass
    
    @abstractmethod
    async def scan(self, ctx: ScanContext) -> ScanResult:
        """
        Perform security scan on the text.
        
        Args:
            ctx: Scan context with text and metadata
            
        Returns:
            ScanResult indicating if content is safe or should be blocked
        """
        pass
    
    async def health_check(self) -> bool:
        """Check if layer is operational. Override for custom checks."""
        return True
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name}>"
