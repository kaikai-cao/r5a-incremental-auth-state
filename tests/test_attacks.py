"""T1–T12 指定攻击测试。每个用例独立构造 Registry，避免相互污染。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from src.aggregate import (
    AGENT_LEAF_PREFIX,
    Aggregate,
    Capability,
    Grant,
    Rejected,
    deserialize_agent_leaf,
    recompute_aggregate,
)
from src.registry import AuthorizationRegistry
from src.verifier import (
    TrustedCheckpoint,
    verify_agent_leaf_commitment,
    verify_inner_root,
    verify_leaf_set_consistency,
    verify_state_proof,
)


def mk(gid: bytes, agent: bytes, cap: Capability, budget: int) -> Grant:
    return Grant(gid, agent, b"ISSUER", cap, budget)


def checkpoints(reg):
    """测试辅助：仅从本次实际转换构造与 Registry 一致的检查点。

    这不意味着 Registry 自己生成的检查点天然可信；验证者必须从外部可信来源取得。
    """
    old_root, new_root, version_before, version_after = reg._last_transition
    return (
        TrustedCheckpoint(root=old_root, version=version_before),
        TrustedCheckpoint(root=new_root, version=version_after),
    )


def expect_rejected(fn, reason: str):
    with pytest.raises(Rejected) as exc:
        fn()
    assert exc.value.reason == reason, (exc.value.reason, reason)


def test_T1_mixed_capability_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    before = reg.state_snapshot()
    expect_rejected(
        lambda: reg.register(mk(b"g2", b"A", Capability.DELETE, 10)),
        "POLICY_VIOLATION",
    )
    assert reg.state_snapshot() == before


def test_T2_revoke_one_of_two_exports_keeps_count():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    reg.register(mk(b"g2", b"A", Capability.EXPORT, 20))
    reg.revoke(b"A", b"g1", expected_version=2)
    agg = reg.get_agent_state(b"A").aggregate
    assert agg.export_count == 1
    assert agg.budget_sum == 20
    assert agg == recompute_aggregate(reg.active_grants(b"A"))


def test_T3_revoke_nonexistent_rejected():
    reg = AuthorizationRegistry()
    before = reg.state_snapshot()
    expect_rejected(lambda: reg.revoke(b"A", b"ghost"), "GRANT_NOT_FOUND")
    assert reg.state_snapshot() == before


def test_T4_stale_version_rejected_twice():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 5), expected_version=0)
    snapshot = reg.state_snapshot()
    expect_rejected(
        lambda: reg.register(mk(b"g2", b"A", Capability.EXPORT, 5), expected_version=0),
        "VERSION_MISMATCH",
    )
    assert reg.state_snapshot() == snapshot
    expect_rejected(
        lambda: reg.revoke(b"A", b"g1", expected_version=0),
        "VERSION_MISMATCH",
    )
    assert reg.state_snapshot() == snapshot


def test_T5_tampered_proof_and_commitments_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    reg.register(mk(b"g2", b"A", Capability.EXPORT, 20))
    proof = reg.build_state_proof(b"A", b"g1")
    cps = checkpoints(reg)
    assert verify_state_proof(proof, *cps)

    # 1) 篡改兄弟路径字节
    siblings = list(proof.inner_proof.siblings)
    siblings[3] = bytes([siblings[3][0] ^ 0x01]) + siblings[3][1:]
    tampered_path = replace(
        proof, inner_proof=replace(proof.inner_proof, siblings=tuple(siblings))
    )
    assert not verify_state_proof(tampered_path, *cps)

    # 2) 篡改状态叶中的聚合摘要
    bad_leaf = bytearray(proof.agent_proof.value)
    bad_leaf[-1] ^= 0x01
    tampered_agg = replace(
        proof, agent_proof=replace(proof.agent_proof, value=bytes(bad_leaf))
    )
    assert not verify_state_proof(tampered_agg, *cps)

    # 3) 篡改状态叶中的内层根
    bad_root_leaf = bytearray(proof.agent_proof.value)
    prefix_len = len(AGENT_LEAF_PREFIX)
    bad_root_leaf[prefix_len] ^= 0x01
    inner_root, aggregate = deserialize_agent_leaf(proof.agent_proof.value)
    assert not verify_agent_leaf_commitment(
        bytes(bad_root_leaf), inner_root, aggregate
    )

    # 4) 篡改全局根
    tampered_global = replace(proof, global_root=b"\x42" * 32)
    assert not verify_state_proof(tampered_global, *cps)

    # 5) 篡改转换 version
    tampered_version = replace(proof, version_after=999)
    assert not verify_state_proof(tampered_version, *cps)


def test_T6_agent_b_grant_cannot_enter_agent_a():
    reg = AuthorizationRegistry()
    reg.register(mk(b"gB", b"B", Capability.EXPORT, 10))
    expect_rejected(lambda: reg.revoke(b"A", b"gB"), "GRANT_NOT_FOUND")
    expect_rejected(
        lambda: reg.gateway_authorize(b"A", b"gB", 1), "GRANT_NOT_FOUND"
    )
    b_proof = reg.build_state_proof(b"B", b"gB")
    forged = replace(b_proof, agent_tag=b"A")
    assert not verify_state_proof(forged, *checkpoints(reg))
    assert not verify_inner_root(b_proof.inner_proof, b"\x00" * 32)


def test_T7_unregistered_grant_gateway_rejected():
    reg = AuthorizationRegistry()
    expect_rejected(
        lambda: reg.gateway_authorize(b"A", b"unregistered", 0), "GRANT_NOT_FOUND"
    )
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    expect_rejected(
        lambda: reg.gateway_authorize(b"A", b"unregistered", 1), "GRANT_NOT_FOUND"
    )


def test_T8_budget_cap_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 80))
    before = reg.state_snapshot()
    expect_rejected(
        lambda: reg.register(mk(b"g2", b"A", Capability.EXPORT, 30)),
        "POLICY_VIOLATION",
    )
    assert reg.state_snapshot() == before
    assert reg.get_agent_state(b"A").aggregate.budget_sum == 80


def test_T9_nonempty_genesis_rejected():
    expect_rejected(
        lambda: AuthorizationRegistry(genesis=Aggregate(0, 0, 1)),
        "INVALID_GENESIS",
    )


def test_T10_duplicate_grant_id_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    before = reg.state_snapshot()
    expect_rejected(
        lambda: reg.register(mk(b"g1", b"A", Capability.EXPORT, 10)),
        "DUPLICATE_GRANT_ID",
    )
    assert reg.state_snapshot() == before
    # grant_id 唯一性是「同一 Agent 内」；不同 Agent 使用同名 grant_id 合法。
    reg.register(mk(b"g1", b"B", Capability.EXPORT, 10))
    assert reg.get_agent_state(b"B").aggregate.export_count == 1


def test_T11_double_revoke_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    reg.revoke(b"A", b"g1", expected_version=1)
    before = reg.state_snapshot()
    expect_rejected(lambda: reg.revoke(b"A", b"g1", expected_version=2), "GRANT_NOT_FOUND")
    assert reg.state_snapshot() == before


def test_T12_forged_budget_cannot_affect_revoke():
    reg = AuthorizationRegistry()
    original = mk(b"g1", b"A", Capability.EXPORT, 30)
    reg.register(original)
    forged = replace(original, budget=1)
    assert forged != original

    stored = reg.active_grants(b"A")[0]
    assert stored.budget == 30
    with pytest.raises(FrozenInstanceError):
        stored.budget = 1

    reg.revoke(b"A", b"g1", expected_version=1)
    assert reg.get_agent_state(b"A").aggregate == recompute_aggregate(
        reg.active_grants(b"A")
    )
    assert reg.get_agent_state(b"A").aggregate.budget_sum == 0


def test_T13_revoked_grant_id_cannot_be_reused():
    """撤销后叶子保留为 tombstone；原 grant_id 在 ACTIVE 与 REVOKED 中都不可复用。"""
    reg = AuthorizationRegistry()
    original = mk(b"g1", b"A", Capability.EXPORT, 10)
    reg.register(original)
    reg.revoke(b"A", b"g1", expected_version=1)
    before = reg.state_snapshot()

    expect_rejected(lambda: reg.register(original, expected_version=2), "GRANT_ID_REUSED")
    expect_rejected(
        lambda: reg.register(
            mk(b"g1", b"A", Capability.DELETE, 1), expected_version=2
        ),
        "GRANT_ID_REUSED",
    )
    assert reg.state_snapshot() == before
    assert reg.active_grants(b"A") == ()
    assert reg.get_agent_state(b"A").aggregate == Aggregate(0, 0, 0)


def test_T14_aggregate_vs_leaf_set_consistency():
    """摘要与所给授权叶不一致时必须拒绝。

    边界：此验证需要枚举全部叶证明，属于全量扫描诊断；它不证明「没有遗漏的叶」，
    也不证明状态转换正确性。不扫描全部叶的聚合一致性验证 **未实现**。
    """
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    reg.register(mk(b"g2", b"A", Capability.EXPORT, 20))
    state = reg.get_agent_state(b"A")
    proofs = reg.all_leaf_proofs(b"A")

    assert verify_leaf_set_consistency(proofs, state.inner_root, state.aggregate)
    assert not verify_leaf_set_consistency(
        proofs, state.inner_root, Aggregate(1, 0, 10)
    )
    assert not verify_leaf_set_consistency(
        proofs[:1], state.inner_root, state.aggregate
    )
    bad_proof = replace(proofs[0], value=b"tampered-leaf-value")
    assert not verify_leaf_set_consistency(
        [bad_proof, *proofs[1:]], state.inner_root, state.aggregate
    )


def test_T15_state_proof_version_tamper_rejected():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", b"A", Capability.EXPORT, 10))
    proof = reg.build_state_proof(b"A", b"g1")
    cps = checkpoints(reg)
    assert verify_state_proof(proof, *cps)
    assert not verify_state_proof(replace(proof, version=999), *cps)
