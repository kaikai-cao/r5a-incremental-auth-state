"""R5-A 独立验证器。

本模块不读取 Registry 内部字典，也不复用 smt.SMT 的树状态。
它把收到的证明字节视为不可信，独立重算哈希路径与承诺。

验证内容是「哈希承诺与路径自洽」，不是零知识证明，也不是电路证明。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .aggregate import (
    Aggregate,
    Rejected,
    deserialize_agent_leaf,
    deserialize_grant,
    deserialize_tombstone,
    is_tombstone,
    recompute_aggregate,
)
from .smt import (
    DEPTH,
    EMPTY_DOMAIN,
    LEAF_DOMAIN,
    NODE_DOMAIN,
    SMTProof,
)


def _leaf(value: bytes) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + value).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


_EMPTY_LEAF = _leaf(EMPTY_DOMAIN + b"empty")
_EMPTY_HASHES: list[bytes] = [b""] * (DEPTH + 1)
_EMPTY_HASHES[DEPTH] = _EMPTY_LEAF
for _d in range(DEPTH - 1, -1, -1):
    _EMPTY_HASHES[_d] = _node(_EMPTY_HASHES[_d + 1], _EMPTY_HASHES[_d + 1])


def verify_path(key: bytes, value: bytes | None, siblings, root: bytes) -> bool:
    """独立验证 256 层 SMT 路径；value=None 表示非成员证明。"""
    if not isinstance(key, bytes) or len(key) == 0:
        return False
    if len(siblings) != DEPTH:
        return False
    if not isinstance(root, bytes) or len(root) != 32:
        return False
    path = int.from_bytes(hashlib.sha256(key).digest(), "big")
    current = _leaf(value) if value is not None else _EMPTY_LEAF
    for depth in range(DEPTH - 1, -1, -1):
        sibling = siblings[depth]
        if not isinstance(sibling, bytes) or len(sibling) != 32:
            return False
        goes_right = (path >> (DEPTH - 1 - depth)) & 1
        current = _node(sibling, current) if goes_right else _node(current, sibling)
    return current == root


def verify_membership(proof: SMTProof) -> bool:
    return proof.value is not None and verify_path(
        proof.key, proof.value, proof.siblings, proof.root
    )


def verify_nonmembership(proof: SMTProof) -> bool:
    return proof.value is None and verify_path(
        proof.key, None, proof.siblings, proof.root
    )


def verify_inner_root(inner_proof: SMTProof, inner_root: bytes) -> bool:
    """验证内层 root 承诺了给定授权叶（或非成员空叶）。"""
    return verify_path(
        inner_proof.key, inner_proof.value, inner_proof.siblings, inner_root
    )


def verify_outer_root(agent_proof: SMTProof, global_root: bytes) -> bool:
    """验证外层 root 承诺了给定 Agent 状态叶。"""
    return verify_path(
        agent_proof.key, agent_proof.value, agent_proof.siblings, global_root
    )


def verify_agent_leaf_commitment(
    leaf_value: bytes, inner_root: bytes, aggregate: Aggregate
) -> bool:
    """验证 Agent 状态叶确实承诺了 inner_root 与 aggregate。"""
    try:
        decoded_root, decoded_agg = deserialize_agent_leaf(leaf_value)
    except (Rejected, ValueError, TypeError):
        return False
    return decoded_root == inner_root and decoded_agg == aggregate


def verify_leaf_set_consistency(
    leaf_proofs,
    inner_root: bytes,
    committed_aggregate: Aggregate,
) -> bool:
    """验证「所给叶集合」的 ACTIVE 聚合是否等于承诺摘要。

    边界（重要）：
      - 需要调用方枚举全部叶证明，因此它是**全量扫描**诊断，不是不扫描的验证；
      - 它只能检查所给叶与摘要一致，**不能证明没有遗漏的叶**；
      - 它不是 ZK 证明，也不证明状态转换正确性。
    """
    # R5-A-R2 / T16：聚合前先拒绝重复 key、重复路径标识。
    # 路径标识是 SHA-256(key)，与 SMT 的键哈希一致；重复提交同一有效证明
    # 会让同一授权被重复计入聚合，因此必须在这里截断。
    seen_keys: set[bytes] = set()
    seen_path_ids: set[bytes] = set()
    active_grants = []
    for proof in leaf_proofs:
        if not isinstance(proof.key, bytes) or len(proof.key) == 0:
            return False
        if proof.key in seen_keys:
            return False
        path_id = hashlib.sha256(proof.key).digest()
        if path_id in seen_path_ids:
            return False
        seen_keys.add(proof.key)
        seen_path_ids.add(path_id)
        if not verify_path(proof.key, proof.value, proof.siblings, inner_root):
            return False
        if proof.value is None:
            return False
        if is_tombstone(proof.value):
            try:
                revoked = deserialize_tombstone(proof.value)
            except (Rejected, ValueError, TypeError):
                return False
            if revoked.grant_id != proof.key:
                return False
            continue
        try:
            grant = deserialize_grant(proof.value)
        except (Rejected, ValueError, TypeError):
            return False
        if grant.grant_id != proof.key:
            return False
        active_grants.append(grant)
    try:
        return recompute_aggregate(active_grants) == committed_aggregate
    except Rejected:
        return False


@dataclass(frozen=True)
class TrustedCheckpoint:
    """外部可信状态检查点：root 与 version 必须成对绑定。

    信任前提：调用方必须保证 checkpoint 来自可信来源（如透明日志、签名公告）。
    本原型不实现检查点签名、共识或透明日志，构造任意 checkpoint 不构成可信事实。
    """

    root: bytes
    version: int


def _valid_checkpoint(checkpoint) -> bool:
    """校验检查点结构；bool 被显式拒绝，因为 bool 是 int 的子类。"""
    return (
        isinstance(checkpoint, TrustedCheckpoint)
        and isinstance(checkpoint.root, bytes)
        and len(checkpoint.root) == 32
        and not isinstance(checkpoint.version, bool)
        and isinstance(checkpoint.version, int)
        and checkpoint.version >= 0
    )


def verify_transition(
    old_root: bytes,
    new_root: bytes,
    version_before: int,
    version_after: int,
    trusted_old: TrustedCheckpoint,
    trusted_new: TrustedCheckpoint,
) -> bool:
    """检查旧根/新根/三个版本字段与可信检查点绑定，且版本递增 1。"""
    if not _valid_checkpoint(trusted_old) or not _valid_checkpoint(trusted_new):
        return False
    for value in (version_before, version_after):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return False
    if not isinstance(old_root, bytes) or len(old_root) != 32:
        return False
    if not isinstance(new_root, bytes) or len(new_root) != 32:
        return False
    if old_root != trusted_old.root or new_root != trusted_new.root:
        return False
    if version_before != trusted_old.version:
        return False
    if version_after != trusted_new.version:
        return False
    return version_after == version_before + 1


@dataclass(frozen=True)
class StateProof:
    agent_tag: bytes
    grant_id: bytes
    version: int
    global_root: bytes
    agent_proof: SMTProof
    inner_proof: SMTProof
    old_global_root: bytes
    new_global_root: bytes
    version_before: int
    version_after: int
    aggregate: Aggregate


def verify_state_proof(
    proof: StateProof,
    trusted_old_checkpoint: TrustedCheckpoint,
    trusted_new_checkpoint: TrustedCheckpoint,
) -> bool:
    """完整状态证明验证：可信根/版本绑定 + 外层/内层承诺 + 键一致性。"""
    if not _valid_checkpoint(trusted_old_checkpoint) or not _valid_checkpoint(
        trusted_new_checkpoint
    ):
        return False
    # R5-A-R2 / T17：三个版本字段和旧/新根都必须绑定外部可信检查点。
    if proof.global_root != trusted_new_checkpoint.root:
        return False
    if proof.new_global_root != trusted_new_checkpoint.root:
        return False
    if proof.old_global_root != trusted_old_checkpoint.root:
        return False
    for value in (proof.version, proof.version_before, proof.version_after):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return False
    if proof.version != trusted_new_checkpoint.version:
        return False
    if proof.version_before != trusted_old_checkpoint.version:
        return False
    if proof.version_after != trusted_new_checkpoint.version:
        return False
    if proof.agent_proof.key != proof.agent_tag:
        return False
    if not verify_outer_root(proof.agent_proof, proof.global_root):
        return False
    if proof.agent_proof.value is None:
        return False
    try:
        inner_root, agg = deserialize_agent_leaf(proof.agent_proof.value)
    except (Rejected, ValueError, TypeError):
        return False
    if agg != proof.aggregate:
        return False
    if not verify_agent_leaf_commitment(proof.agent_proof.value, inner_root, agg):
        return False
    if proof.inner_proof.key != proof.grant_id:
        return False
    if not verify_inner_root(proof.inner_proof, inner_root):
        return False
    if proof.inner_proof.value is not None:
        if is_tombstone(proof.inner_proof.value):
            try:
                revoked = deserialize_tombstone(proof.inner_proof.value)
            except (Rejected, ValueError, TypeError):
                return False
            if (
                revoked.grant_id != proof.grant_id
                or revoked.agent_tag != proof.agent_tag
            ):
                return False
        else:
            try:
                grant = deserialize_grant(proof.inner_proof.value)
            except (Rejected, ValueError, TypeError):
                return False
            if grant.grant_id != proof.grant_id or grant.agent_tag != proof.agent_tag:
                return False
    return verify_transition(
        proof.old_global_root,
        proof.new_global_root,
        proof.version_before,
        proof.version_after,
        trusted_old_checkpoint,
        trusted_new_checkpoint,
    )
