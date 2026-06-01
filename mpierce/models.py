# mpierce/models.py
from dataclasses import dataclass, field
from typing import Optional


class Verdict:
    VULNERABLE = "VULNERABLE"
    NOT_DETECTED = "NOT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class HttpExchange:
    method: str
    url: str
    host: str
    port: int
    protocol: str
    path: str
    status: Optional[int]
    mimetype: Optional[str]
    request_headers: dict
    request_body: str
    response_headers: dict
    response_body: str
    raw_request: str
    raw_response: str


@dataclass
class Candidate:
    method: str
    url: str
    path: str
    location: str            # login|forgot-password|registration|account-update|account-lookup|lockout|other
    identifier_param: str
    param_location: str      # query|form|json|path
    reason: str


@dataclass
class Identifier:
    value: str
    type: str                # email|username|id
    source: str


@dataclass
class Response:
    status: Optional[int]
    headers: dict
    body: str
    elapsed_ms: float
    error: Optional[str] = None


@dataclass
class SignalVerdict:
    signal: str
    verdict: str
    confidence: str          # high|medium|low
    evidence: str


@dataclass
class ValueResult:
    value: str
    verdicts: list = field(default_factory=list)   # list[SignalVerdict]

    @property
    def enumerable(self) -> bool:
        """True when this value's responses differ from the nonexistent
        baseline on any signal (i.e. the app reveals it exists)."""
        return any(v.verdict == Verdict.VULNERABLE for v in self.verdicts)


@dataclass
class Finding:
    candidate: Candidate
    identifier_param: str
    nonexistent_value: str
    results: list = field(default_factory=list)   # list[ValueResult]
