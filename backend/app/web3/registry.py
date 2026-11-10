"""Web3 integration: commit report hashes to the ThreatRegistry contract.

Only the SHA-256 of a report's canonical JSON and a coarse category tag ever
leave the backend. Raw URLs, message text, and personal data never go on-chain.

The chain client is optional: when TRUSTLENS_REGISTRY_ADDRESS is unset (or the
node is unreachable) every chain feature degrades to "unavailable" instead of
failing the analysis pipeline.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import pathlib
import re
from typing import Optional, Protocol

from ..config import Settings

logger = logging.getLogger("trustlens.web3")

STATUS_NAMES = {0: "submitted", 1: "validated", 2: "disputed"}

# Coarse, fixed category tags — nothing user-supplied goes on-chain.
CATEGORY_URL_ANALYSIS = "url-analysis"
CATEGORY_MESSAGE_ANALYSIS = "message-analysis"

MINIMAL_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"internalType": "string", "name": "category", "type": "string"},
        ],
        "name": "submitReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "getReport",
        "outputs": [
            {"internalType": "address", "name": "reporter", "type": "address"},
            {"internalType": "uint64", "name": "submittedAt", "type": "uint64"},
            {"internalType": "string", "name": "category", "type": "string"},
            {"internalType": "enum ThreatRegistry.Status", "name": "status", "type": "uint8"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "verify",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "getRevisionCount",
        "outputs": [{"internalType": "uint32", "name": "", "type": "uint32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"internalType": "uint32", "name": "index", "type": "uint32"},
        ],
        "name": "getRevision",
        "outputs": [
            {"internalType": "enum ThreatRegistry.Status", "name": "status", "type": "uint8"},
            {"internalType": "address", "name": "updatedBy", "type": "address"},
            {"internalType": "uint64", "name": "updatedAt", "type": "uint64"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]


# Fields excluded from the canonical-JSON hash. Must match
# app.pipeline.runner.CANONICAL_EXCLUDE: the integrity carrier itself and the
# regenerable explanation output.
CANONICAL_EXCLUDE = {"integrity", "explanation"}


def recompute_report_hash(stored_report: dict) -> str:
    """Recompute the canonical-JSON SHA-256 of a stored report dict.

    Mirrors pipeline.runner._canonical_hash: drop the excluded fields, serialise
    with sorted keys and compact separators, SHA-256 over UTF-8 bytes.
    """
    payload = {k: v for k, v in stored_report.items() if k not in CANONICAL_EXCLUDE}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def chain_enabled(settings: Settings) -> bool:
    return bool(registry_address_of(settings)) and settings.chain_enabled


def registry_address_of(settings: Settings) -> str:
    """Explicit setting first; else a Hardhat deployment JSON file (compose wiring)."""
    if settings.registry_address:
        return settings.registry_address
    if settings.deployment_file:
        try:
            import pathlib

            data = json.loads(pathlib.Path(settings.deployment_file).read_text(encoding="utf-8"))
            address = data.get("address") or ""
            if re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                return address
        except (OSError, ValueError):
            pass
    return ""


def parse_report_hash(hex_hash: str) -> bytes:
    """'0x…64 hex' -> 32 bytes; raises ValueError on bad input."""
    text = hex_hash.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("report hash must be a 32-byte hex string (0x + 64 hex chars)")
    return bytes.fromhex(text)


class RegistryClient:
    """Blocking web3.py client; route handlers wrap calls in asyncio.to_thread.

    Hardhat-state resilience (bonus): the local Hardhat node is in-memory, so a
    restart wipes the deployed contract while ``TRUSTLENS_REGISTRY_ADDRESS``
    (or the deployment JSON) still points at the old address — contract calls
    then answer with empty code ("0x"). When that happens, the client
    re-reads TRUSTLENS_DEPLOYMENT_FILE (mtime-checked) and rebinds to the
    fresh address once before failing.
    """

    def __init__(self, rpc_url: str, contract_address: str, private_key: str,
                 deployment_file: str = ""):
        self._rpc_url = rpc_url
        self._address = contract_address
        self._private_key = private_key
        self._deployment_file = deployment_file
        self._deployment_mtime: float | None = None
        if deployment_file:
            try:
                self._deployment_mtime = os.path.getmtime(deployment_file)
            except OSError:
                self._deployment_mtime = None
        self._w3 = None
        self._contract = None

    def _ensure(self):
        if self._contract is not None:
            return
        from web3 import Web3  # imported lazily: chain features are optional

        self._w3 = Web3(Web3.HTTPProvider(self._rpc_url, request_kwargs={"timeout": 15}))
        self._contract = self._w3.eth.contract(
            address=self._w3.to_checksum_address(self._address), abi=MINIMAL_ABI
        )

    def _recovered_contract_address(self, force: bool = False) -> Optional[str]:
        """Re-read the deployment JSON (mtime-checked); return the address when
        it CHANGED, else None."""
        if not self._deployment_file:
            return None
        try:
            mtime = os.path.getmtime(self._deployment_file)
        except OSError:
            return None
        if not force and self._deployment_mtime is not None and mtime == self._deployment_mtime:
            return None
        self._deployment_mtime = mtime
        try:
            data = json.loads(pathlib.Path(self._deployment_file).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        address = data.get("address") or ""
        if re.fullmatch(r"0x[0-9a-fA-F]{40}", address) and address.lower() != self._address.lower():
            return address
        return None

    @staticmethod
    def _is_empty_code_error(exc: BaseException) -> bool:
        """True when a call failed because no contract code exists at the
        configured address (eth_call answered '0x')."""
        from web3.exceptions import BadFunctionCallOutput, ContractLogicError

        if isinstance(exc, BadFunctionCallOutput):
            return True
        if isinstance(exc, ContractLogicError):
            return str(exc).strip().rstrip("'\"") in ("0x", "b''", "")
        text = str(exc)
        return "return data: b''" in text or "Could not decode" in text and "b''" in text

    def _recover_from_empty_code(self) -> bool:
        """Rebind to the freshly deployed address; True when recovery happened."""
        new_address = self._recovered_contract_address(force=True)
        if new_address is None:
            return False
        logger.warning(
            "no contract code at %s (local node restarted?); re-reading %s -> %s",
            self._address, self._deployment_file, new_address,
        )
        self._address = new_address
        self._contract = None  # force a rebuild at the fresh address
        self._ensure()
        return True

    def _call_with_recovery(self, fn, *args):
        """Run a contract call; on an empty-code answer, rebind once to the
        freshly deployed address and retry."""
        self._ensure()
        try:
            return fn(*args)
        except Exception as exc:
            if not self._is_empty_code_error(exc) or not self._recover_from_empty_code():
                raise
            logger.info("retrying chain call after deployment refresh")
            return fn(*args)

    def is_connected(self) -> bool:
        try:
            self._ensure()
            return bool(self._w3.is_connected())  # type: ignore[union-attr]
        except Exception:
            return False

    def get_chain_id(self) -> int:
        self._ensure()
        assert self._w3 is not None
        return int(self._w3.eth.chain_id)

    def submit(self, report_hash: bytes, category: str) -> dict:
        """Send submitReport and wait for the receipt. Returns tx details."""
        if not self._private_key:
            raise RuntimeError("TRUSTLENS_CHAIN_PRIVATE_KEY is not set; cannot send transactions")

        def _send() -> dict:
            assert self._w3 is not None and self._contract is not None
            account = self._w3.eth.account.from_key(self._private_key)
            tx = self._contract.functions.submitReport(report_hash, category).build_transaction({
                "from": account.address,
                "nonce": self._w3.eth.get_transaction_count(account.address),
                "gas": 200_000,
                "maxFeePerGas": self._w3.to_wei(50, "gwei"),
                "maxPriorityFeePerGas": self._w3.to_wei(2, "gwei"),
                "chainId": self._w3.eth.chain_id,
            })
            signed = account.sign_transaction(tx)
            tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            if receipt.status != 1:
                raise RuntimeError(f"submitReport transaction reverted (tx {tx_hash.hex()})")
            return {
                "tx_hash": tx_hash.hex(),
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "block_timestamp": self._w3.eth.get_block(receipt.blockNumber).timestamp,
            }

        return self._call_with_recovery(_send)

    def verify(self, report_hash: bytes) -> dict:
        """Read-only on-chain check of a report hash."""

        def _read() -> dict:
            assert self._contract is not None
            exists = bool(self._contract.functions.verify(report_hash).call())
            result: dict = {"exists": exists}
            if exists:
                reporter, submitted_at, category, status = self._contract.functions.getReport(
                    report_hash
                ).call()
                revision_count = self._contract.functions.getRevisionCount(report_hash).call()
                result.update(
                    reporter=reporter,
                    submitted_at=int(submitted_at),
                    category=category,
                    status=STATUS_NAMES.get(int(status), f"unknown({status})"),
                    revision_count=int(revision_count),
                )
            return result

        return self._call_with_recovery(_read)


class RegistryClientProtocol(Protocol):
    """Structural type for injected (stub) clients in tests."""

    def is_connected(self) -> bool: ...
    def submit(self, report_hash: bytes, category: str) -> dict: ...
    def verify(self, report_hash: bytes) -> dict: ...


class ChainUnavailableError(Exception):
    """The chain node is unreachable or the contract call failed."""


async def to_chain_error(exc: Exception) -> ChainUnavailableError:
    return ChainUnavailableError(f"{type(exc).__name__}: {str(exc)[:250]}")


def build_registry_client(settings: Settings) -> Optional[RegistryClientProtocol]:
    """Construct the client when chain features are configured, else None."""
    address = registry_address_of(settings)
    if not address or not settings.chain_enabled:
        return None
    # Prioritise runtime Vercel service binding if present
    rpc_url = os.getenv("CONTRACTS_URL") or settings.chain_rpc_url
    return RegistryClient(
        rpc_url=rpc_url,
        contract_address=address,
        private_key=settings.chain_private_key,
        deployment_file=settings.deployment_file,
    )


async def run_chain(fn, *args):
    """Run a blocking chain call in a thread, normalising failures."""
    try:
        return await asyncio.to_thread(fn, *args)
    except Exception as exc:  # noqa: BLE001 - any web3 error becomes ChainUnavailable
        raise await to_chain_error(exc) from exc
