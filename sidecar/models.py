from dataclasses import dataclass


@dataclass(slots=True)
class Decision:
    allowed: bool
    reason: str

    @property
    def status_code(self) -> int:
        return 200 if self.allowed else 403
