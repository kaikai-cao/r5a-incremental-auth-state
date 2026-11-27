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


def verify_transition(
    old_root: bytes,
    new_root: bytes,
    version_before: int,
    version_after: int,
    trusted_old_root: bytes,
    trusted_root: bytes,
) -> bool:
    """检查旧根/新根/version 与可信快照一致。"""
    if not isinstance(version_before, int) or not isinstance(version_after, int):
        return False
    if not isinstance(old_root, bytes) or len(old_root) != 32:
        return False
    if not isinstance(new_root, bytes) or len(new_root) != 32:
        return False
    if old_root != trusted_old_root or new_root != trusted_root:
        return False
    if version_before == 0 and version_after == 0:
        return old_root == new_root
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
    proof: StateProof, trusted_root: bytes, trusted_old_root: bytes
) -> bool:
    """完整状态证明验证：外层承诺 + 内层承诺 + 键一致性 + 转换一致性。"""
    if proof.global_root != trusted_root:
        return False
    if proof.new_global_root != trusted_root:
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
        trusted_old_root,
        trusted_root,
    )
