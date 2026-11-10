"""Enumerations shared across the pipeline, scoring engine, and API."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    INCONCLUSIVE = "inconclusive"


class InputType(str, Enum):
    URL = "url"
    MESSAGE = "message"


class FindingCategory(str, Enum):
    NORMALIZATION = "normalization"
    DOMAIN = "domain"
    FETCH = "fetch"
    TLS = "tls"
    INTEL = "intel"
    HEADERS = "headers"
    MESSAGE = "message"
    CORRELATION = "correlation"
    DNS = "dns"
    SYSTEM = "system"


class FetchErrorKind(str, Enum):
    NONE = "none"
    DNS = "dns"
    POLICY = "policy"        # refused by SSRF/security policy (never contacted)
    TIMEOUT = "timeout"
    TLS = "tls"
    CONNECTION = "connection"
    HTTP = "http"            # protocol-level error
    SIZE = "size"
    OTHER = "other"
