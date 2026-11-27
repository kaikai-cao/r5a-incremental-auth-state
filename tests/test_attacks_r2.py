"""R5-A-R2：T16 重复叶证明、T17 可信检查点版本绑定、T18 多发行者记录。

边界：本文件只验证 Python 哈希承诺与 Registry 行为，不是 ZKP 证明，
也不实现检查点签名、共识、完整集合证明或状态转换证明。
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.aggregate import (
    Aggregate,
    Capability,
    Grant,
    Rejected,
    deserialize_grant,
)
from src.registry import AuthorizationRegistry
from src.verifier import (
    TrustedCheckpoint,
    verify_inner_root,
    verify_leaf_set_consistency,
    verify_membership,
    verify_state_proof,
    verify_transition,
)


def checkpoints(reg):
    """测试辅助：从本次实际转换构造检查点。

    这不代表 Registry 自生成的检查点天然可信；验证者必须从外部可信来源取得。
    """
    old_root, new_root, version_before, version_after = reg._last_transition
    return (
        TrustedCheckpoint(root=old_root, version=version_before),
        TrustedCheckpoint(root=new_root, version=version_after),
    )


def grant(gid: bytes, issuer: bytes, budget: int, agent: bytes = b"A") -> Grant:
    return Grant(gid, agent, issuer, Capability.EXPORT, budget)


def expect_rejected(fn, reason: str):
    with pytest.raises(Rejected) as exc:
        fn()
    assert exc.value.reason == reason


# ---------------------------------------------------------------------------
# T16：拒绝重复叶证明
# ---------------------------------------------------------------------------


def test_T16_A_unique_leaf_set_accepted():
    """两份不同授权的有效证明，摘要正确，验证通过。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    reg.register(grant(b"g2", b"ISSUER", 20))
    state = reg.get_agent_state(b"A")
    proofs = reg.all_leaf_proofs(b"A")
    assert len(proofs) == 2
    assert verify_leaf_set_consistency(proofs, state.inner_root, state.aggregate)


def test_T16_B_exact_duplicate_proof_rejected():
    """[proof, proof, other] 必须拒绝。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    reg.register(grant(b"g2", b"ISSUER", 20))
    state = reg.get_agent_state(b"A")
    p1, p2 = reg.all_leaf_proofs(b"A")
    assert not verify_leaf_set_consistency(
        [p1, p1, p2], state.inner_root, state.aggregate
    )


def test_T16_C_non_adjacent_duplicate_rejected():
    """重复证明在不相邻位置同样必须拒绝。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    reg.register(grant(b"g2", b"ISSUER", 20))
    reg.register(grant(b"g3", b"ISSUER", 5))
    state = reg.get_agent_state(b"A")
    p1, p2, p3 = reg.all_leaf_proofs(b"A")
    assert not verify_leaf_set_consistency(
        [p1, p2, p3, p1], state.inner_root, state.aggregate
    )
    assert not verify_leaf_set_consistency(
        [p3, p1, p2, p3], state.inner_root, state.aggregate
    )


def test_T16_D_missing_active_leaf_rejected():
    """遗漏 ACTIVE 叶导致摘要不一致时必须拒绝。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    reg.register(grant(b"g2", b"ISSUER", 20))
    state = reg.get_agent_state(b"A")
    proofs = reg.all_leaf_proofs(b"A")
    assert not verify_leaf_set_consistency(
        proofs[:1], state.inner_root, state.aggregate
    )
    assert not verify_leaf_set_consistency(
        proofs, state.inner_root, Aggregate(1, 0, 30)
    )


def test_T16_E_missing_tombstone_is_known_limitation():
    """已知限制演示：只提交 g2、不提交已撤销 g1 的墓碑，当前仍会通过。

    这不是验收通过项，而是明确记录：verify_leaf_set_consistency 只能检查
    「已提供集合」的摘要一致性，无法证明集合完整（没有遗漏的 tombstone 或
    其他不影响聚合的叶）。完整集合证明未实现。
    """
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    reg.revoke(b"A", b"g1", expected_version=1)
    reg.register(grant(b"g2", b"ISSUER", 20))
    state = reg.get_agent_state(b"A")
    g2_proof = reg.prove_grant(b"A", b"g2")

    # 断言当前行为，作为限制基线；若将来实现完整集合证明，此断言应改为 False。
    assert verify_leaf_set_consistency(
        [g2_proof], state.inner_root, state.aggregate
    )
    assert state.aggregate == Aggregate(1, 0, 20)


def test_T16_F_invalid_key_rejected():
    """空 key 与非 bytes key 必须在计算路径标识前被拒绝。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    state = reg.get_agent_state(b"A")
    proof = reg.all_leaf_proofs(b"A")[0]
    assert not verify_leaf_set_consistency(
        [replace(proof, key=b"")], state.inner_root, state.aggregate
    )
    assert not verify_leaf_set_consistency(
        [replace(proof, key="g1")], state.inner_root, state.aggregate
    )


# ---------------------------------------------------------------------------
# T17：版本字段绑定可信检查点
# ---------------------------------------------------------------------------


def test_T17_A_real_checkpoints_accepted():
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    assert verify_state_proof(proof, *checkpoints(reg))


def test_T17_B_version_field_tamper_rejected():
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    assert not verify_state_proof(replace(proof, version=999), *checkpoints(reg))


def test_T17_C_all_three_version_fields_tampered_rejected():
    """三个版本字段同时伪造且保持递增关系，仍须被可信检查点拒绝。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    tampered = replace(
        proof, version_before=100, version_after=101, version=101
    )
    assert not verify_state_proof(tampered, *checkpoints(reg))


def test_T17_D_wrong_new_checkpoint_version_rejected():
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    old_cp, new_cp = checkpoints(reg)
    bad_cp = TrustedCheckpoint(root=new_cp.root, version=new_cp.version + 7)
    assert not verify_state_proof(proof, old_cp, bad_cp)


def test_T17_E_wrong_checkpoint_root_rejected():
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    old_cp, new_cp = checkpoints(reg)
    assert not verify_state_proof(
        proof, TrustedCheckpoint(root=b"\x42" * 32, version=old_cp.version), new_cp
    )
    assert not verify_state_proof(
        proof, old_cp, TrustedCheckpoint(root=b"\x42" * 32, version=new_cp.version)
    )


def test_T17_F_invalid_checkpoint_rejected():
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    old_cp, new_cp = checkpoints(reg)
    invalid = [
        TrustedCheckpoint(root=b"\x11" * 31, version=1),
        TrustedCheckpoint(root=b"\x11" * 33, version=1),
        TrustedCheckpoint(root=b"\x11" * 32, version=-1),
        TrustedCheckpoint(root=b"\x11" * 32, version=True),
        TrustedCheckpoint(root=b"\x11" * 32, version="1"),
    ]
    for cp in invalid:
        assert not verify_state_proof(proof, cp, new_cp)
        assert not verify_state_proof(proof, old_cp, cp)
        assert not verify_transition(
            proof.old_global_root,
            proof.new_global_root,
            proof.version_before,
            proof.version_after,
            cp,
            new_cp,
        )


def test_T17_G_transition_binds_all_version_fields():
    """verify_transition 同样拒绝三字段同步伪造（无旧接口可绕过）。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"g1", b"ISSUER", 10))
    proof = reg.build_state_proof(b"A", b"g1")
    old_cp, new_cp = checkpoints(reg)
    assert verify_transition(
        proof.old_global_root,
        proof.new_global_root,
        proof.version_before,
        proof.version_after,
        old_cp,
        new_cp,
    )
    assert not verify_transition(
        proof.old_global_root,
        proof.new_global_root,
        100,
        101,
        old_cp,
        new_cp,
    )


# ---------------------------------------------------------------------------
# T18：两个不同 issuer 的记录进入同一 Agent 聚合
# ---------------------------------------------------------------------------


def test_T18_two_issuers_same_agent():
    reg = AuthorizationRegistry()
    grant_a = grant(b"grant-from-issuer-a", b"ISSUER-A", 10)
    grant_b = grant(b"grant-from-issuer-b", b"ISSUER-B", 20)

    reg.register(grant_a, expected_version=0)
    reg.register(grant_b, expected_version=1)
    state = reg.get_agent_state(b"A")
    assert state.aggregate == Aggregate(2, 0, 30)

    proof_a = reg.prove_grant(b"A", grant_a.grant_id)
    proof_b = reg.prove_grant(b"A", grant_b.grant_id)
    assert verify_membership(proof_a)
    assert verify_membership(proof_b)
    assert verify_inner_root(proof_a, state.inner_root)
    assert verify_inner_root(proof_b, state.inner_root)

    # 独立解码证明叶：issuer_id 只是标签，不涉及签名验证。
    record_a = deserialize_grant(proof_a.value)
    record_b = deserialize_grant(proof_b.value)
    assert record_a.issuer_id == b"ISSUER-A"
    assert record_b.issuer_id == b"ISSUER-B"

    reg.revoke(b"A", grant_a.grant_id, expected_version=2)
    assert reg.get_agent_state(b"A").aggregate == Aggregate(1, 0, 20)
    assert reg.gateway_authorize(b"A", grant_b.grant_id, 3).allowed
    expect_rejected(
        lambda: reg.gateway_authorize(b"A", grant_a.grant_id, 3), "GRANT_NOT_FOUND"
    )


def test_T18_same_grant_id_different_issuer_still_rejected():
    """叶位置按 grant_id 唯一，不按 (issuer_id, grant_id) 唯一。"""
    reg = AuthorizationRegistry()
    reg.register(grant(b"shared-id", b"ISSUER-A", 5))
    expect_rejected(
        lambda: reg.register(grant(b"shared-id", b"ISSUER-B", 5)),
        "DUPLICATE_GRANT_ID",
    )
    assert reg.get_agent_state(b"A").aggregate == Aggregate(1, 0, 5)
