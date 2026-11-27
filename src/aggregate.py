"""R5-A 数据结构、序列化与独立全量 Oracle。

本模块只负责：
  - 冻结数据类型（Grant / Capability / Aggregate）；
  - 确定性字节序列化；
  - recompute_aggregate：从授权集合**全量重算**摘要的独立 Oracle。

全量 Oracle 不复用 registry/transition 的增量逻辑，二者是两条独立代码路径。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

UINT64_MAX = (1 << 64) - 1
BUDGET_CAP = 100

GRANT_PREFIX = b"R5A-GRANT-v1"
AGG_PREFIX = b"R5A-AGG-v1"
AGENT_LEAF_PREFIX = b"R5A-AGENTLEAF-v1"
TOMBSTONE_PREFIX = b"R5A-TOMBSTONE-v1"


class Capability(Enum):
    EXPORT = 1
    DELETE = 2


@dataclass(frozen=True)
class Grant:
    grant_id: bytes
    agent_tag: bytes
    issuer_id: bytes
    capability: Capability
    budget: int


@dataclass(frozen=True)
class Aggregate:
    export_count: int
    delete_count: int
    budget_sum: int


ZERO_AGGREGATE = Aggregate(0, 0, 0)


class Rejected(ValueError):
    """统一拒绝异常；reason 为稳定机器可读原因码。"""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def validate_grant(grant: Grant) -> None:
    """校验冻结授权记录；失败抛 Rejected('INVALID_GRANT')。"""
    if not isinstance(grant, Grant):
        raise Rejected("INVALID_GRANT", "not a Grant instance")
    for name in ("grant_id", "agent_tag", "issuer_id"):
        value = getattr(grant, name)
        if not isinstance(value, bytes):
            raise Rejected("INVALID_GRANT", f"{name} is not bytes")
        if len(value) == 0:
            raise Rejected("INVALID_GRANT", f"{name} is empty")
    if not isinstance(grant.capability, Capability):
        raise Rejected("INVALID_GRANT", "capability is not Capability")
    if isinstance(grant.budget, bool) or not isinstance(grant.budget, int):
        raise Rejected("INVALID_GRANT", "budget is not int")
    if grant.budget < 0 or grant.budget > UINT64_MAX:
        raise Rejected("INVALID_GRANT", "budget out of uint64 range")


def recompute_aggregate(active_grants) -> Aggregate:
    """独立全量 Oracle：遍历 ACTIVE 授权集合从头计数/求和。

    不调用 transition.py 的任何增量函数，也不读取 registry 的缓存摘要。
    """
    n_e = 0
    n_d = 0
    total = 0
    for grant in active_grants:
        if grant.capability is Capability.EXPORT:
            n_e += 1
        elif grant.capability is Capability.DELETE:
            n_d += 1
        else:  # pragma: no cover - validate_grant 已阻止
            raise Rejected("INVALID_GRANT", "unknown capability in oracle")
        total += grant.budget
        if total > UINT64_MAX:
            raise Rejected("AGGREGATE_OVERFLOW", "oracle budget_sum overflow")
    return Aggregate(n_e, n_d, total)


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def serialize_grant(grant: Grant) -> bytes:
    return (
        GRANT_PREFIX
        + _lp(grant.grant_id)
        + _lp(grant.agent_tag)
        + _lp(grant.issuer_id)
        + bytes([grant.capability.value])
        + grant.budget.to_bytes(8, "big")
    )


def deserialize_grant(data: bytes) -> Grant:
    if not isinstance(data, bytes) or not data.startswith(GRANT_PREFIX):
        raise Rejected("INVALID_PROOF", "bad grant prefix")
    pos = len(GRANT_PREFIX)

    def read_lp() -> bytes:
        nonlocal pos
        if pos + 4 > len(data):
            raise Rejected("INVALID_PROOF", "truncated grant length")
        size = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if pos + size > len(data):
            raise Rejected("INVALID_PROOF", "truncated grant field")
        out = data[pos : pos + size]
        pos += size
        return out

    grant_id = read_lp()
    agent_tag = read_lp()
    issuer_id = read_lp()
    if pos + 1 > len(data):
        raise Rejected("INVALID_PROOF", "truncated capability")
    cap_value = data[pos]
    pos += 1
    if pos + 8 > len(data):
        raise Rejected("INVALID_PROOF", "truncated budget")
    budget = int.from_bytes(data[pos : pos + 8], "big")
    pos += 8
    if pos != len(data):
        raise Rejected("INVALID_PROOF", "trailing grant bytes")
    try:
        capability = Capability(cap_value)
    except ValueError as exc:
        raise Rejected("INVALID_PROOF", "unknown capability value") from exc
    return Grant(grant_id, agent_tag, issuer_id, capability, budget)


def serialize_tombstone(
    grant_id: bytes, agent_tag: bytes, capability: Capability, budget: int
) -> bytes:
    """撤销后的不可复用墓碑；它占据 grant_id 叶位但不计入 ACTIVE 聚合。"""
    return (
        TOMBSTONE_PREFIX
        + _lp(grant_id)
        + _lp(agent_tag)
        + bytes([capability.value])
        + budget.to_bytes(8, "big")
    )


def is_tombstone(data: bytes | None) -> bool:
    return isinstance(data, bytes) and data.startswith(TOMBSTONE_PREFIX)


def deserialize_tombstone(data: bytes) -> Grant:
    """反序列化墓碑为 Grant 形状的记录，供审计/验证器核对键一致性。"""
    if not is_tombstone(data):
        raise Rejected("INVALID_PROOF", "not a tombstone")
    pos = len(TOMBSTONE_PREFIX)

    def read_lp() -> bytes:
        nonlocal pos
        if pos + 4 > len(data):
            raise Rejected("INVALID_PROOF", "truncated tombstone length")
        size = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if pos + size > len(data):
            raise Rejected("INVALID_PROOF", "truncated tombstone field")
        out = data[pos : pos + size]
        pos += size
        return out

    grant_id = read_lp()
    agent_tag = read_lp()
    if pos + 1 > len(data):
        raise Rejected("INVALID_PROOF", "truncated tombstone capability")
    cap_value = data[pos]
    pos += 1
    if pos + 8 > len(data):
        raise Rejected("INVALID_PROOF", "truncated tombstone budget")
    budget = int.from_bytes(data[pos : pos + 8], "big")
    pos += 8
    if pos != len(data):
        raise Rejected("INVALID_PROOF", "trailing tombstone bytes")
    try:
        capability = Capability(cap_value)
    except ValueError as exc:
        raise Rejected("INVALID_PROOF", "unknown tombstone capability") from exc
    return Grant(grant_id, agent_tag, b"REVOKED", capability, budget)


def serialize_aggregate(agg: Aggregate) -> bytes:
    return (
        AGG_PREFIX
        + agg.export_count.to_bytes(8, "big")
        + agg.delete_count.to_bytes(8, "big")
        + agg.budget_sum.to_bytes(8, "big")
    )


def deserialize_aggregate(data: bytes) -> Aggregate:
    if not isinstance(data, bytes) or not data.startswith(AGG_PREFIX):
        raise Rejected("INVALID_PROOF", "bad aggregate prefix")
    body = data[len(AGG_PREFIX) :]
    if len(body) != 24:
        raise Rejected("INVALID_PROOF", "bad aggregate length")
    return Aggregate(
        int.from_bytes(body[0:8], "big"),
        int.from_bytes(body[8:16], "big"),
        int.from_bytes(body[16:24], "big"),
    )


def serialize_agent_leaf(inner_root: bytes, agg: Aggregate) -> bytes:
    if len(inner_root) != 32:
        raise Rejected("INVALID_STATE", "inner_root must be 32 bytes")
    return AGENT_LEAF_PREFIX + inner_root + serialize_aggregate(agg)


def deserialize_agent_leaf(data: bytes) -> tuple[bytes, Aggregate]:
    if not isinstance(data, bytes) or not data.startswith(AGENT_LEAF_PREFIX):
        raise Rejected("INVALID_PROOF", "bad agent leaf prefix")
    body = data[len(AGENT_LEAF_PREFIX) :]
    if len(body) != 32 + len(AGG_PREFIX) + 24:
        raise Rejected("INVALID_PROOF", "bad agent leaf length")
    return body[:32], deserialize_aggregate(body[32:])
