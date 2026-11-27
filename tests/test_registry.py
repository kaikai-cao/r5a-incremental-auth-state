"""Registry 基础行为：增量/Oracle 一致性、CAS、原子性、Gateway、状态证明。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from src.aggregate import (
    Aggregate,
    Capability,
    Grant,
    Rejected,
    deserialize_agent_leaf,
    recompute_aggregate,
)
from src.registry import AuthorizationRegistry
from src.transition import policy_holds
from src.verifier import (
    TrustedCheckpoint,
    verify_agent_leaf_commitment,
    verify_state_proof,
)


def mk(gid: bytes, agent: bytes = b"A", cap=Capability.EXPORT, budget: int = 10) -> Grant:
    return Grant(gid, agent, b"ISSUER", cap, budget)


def checkpoints(reg):
    """测试辅助：仅用本次实际转换构造检查点；生产验证者必须从外部可信来源取得。"""
    old_root, new_root, version_before, version_after = reg._last_transition
    return (
        TrustedCheckpoint(root=old_root, version=version_before),
        TrustedCheckpoint(root=new_root, version=version_after),
    )


def fingerprint(reg: AuthorizationRegistry):
    return (
        reg.get_version(),
        reg.get_global_root(),
        dict(reg.aggregates),
        {tag: tree.root for tag, tree in reg.inner_smts.items()},
    )


def test_register_matches_oracle_after_each_step():
    reg = AuthorizationRegistry()
    for i in range(12):
        agent = [b"A", b"B", b"C"][i % 3]
        reg.register(mk(f"g{i}".encode(), agent, budget=i % 5))
        state = reg.get_agent_state(agent)
        assert state.aggregate == recompute_aggregate(reg.active_grants(agent))
        assert policy_holds(state.aggregate)
    assert reg.get_version() == 12


def test_cas_rejects_stale_version():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1"), expected_version=0)
    before = fingerprint(reg)
    with pytest.raises(Rejected) as exc:
        reg.register(mk(b"g2"), expected_version=0)
    assert exc.value.reason == "VERSION_MISMATCH"
    assert fingerprint(reg) == before


def test_revoke_uses_stored_record():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", budget=40))
    assert reg.get_agent_state(b"A").aggregate.budget_sum == 40
    reg.revoke(b"A", b"g1", expected_version=1)
    assert reg.get_agent_state(b"A").aggregate == Aggregate(0, 0, 0)
    assert reg.active_grants(b"A") == ()


def test_rejected_operations_are_atomic():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", budget=20))

    cases = [
        lambda: reg.register(mk(b"g1", budget=20)),
        lambda: reg.register(mk(b"g2", budget=90)),
        lambda: reg.revoke(b"A", b"missing"),
        lambda: reg.register(mk(b"g3"), expected_version=0),
        lambda: reg.gateway_authorize(b"A", b"missing", 1),
    ]
    for operation in cases:
        before = fingerprint(reg)
        with pytest.raises(Rejected):
            operation()
        assert fingerprint(reg) == before


def test_nonempty_genesis_rejected():
    with pytest.raises(Rejected) as exc:
        AuthorizationRegistry(genesis=Aggregate(0, 0, 1))
    assert exc.value.reason == "INVALID_GENESIS"


def test_state_proof_verification_and_tampering():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1", budget=10))
    reg.register(mk(b"g2", budget=20))
    proof = reg.build_state_proof(b"A", b"g1")
    cps = checkpoints(reg)

    assert verify_state_proof(proof, *cps)

    tampered_path = replace(
        proof,
        inner_proof=replace(
            proof.inner_proof,
            siblings=(
                bytes([proof.inner_proof.siblings[0][0] ^ 1])
                + proof.inner_proof.siblings[0][1:],
            )
            + proof.inner_proof.siblings[1:],
        ),
    )
    assert not verify_state_proof(tampered_path, *cps)

    tampered_root = replace(proof, global_root=b"\x11" * 32)
    assert not verify_state_proof(tampered_root, *cps)

    tampered_version = replace(proof, version_after=99)
    assert not verify_state_proof(tampered_version, *cps)

    leaf = bytearray(proof.agent_proof.value)
    leaf[-1] ^= 0x01
    inner_root, aggregate = deserialize_agent_leaf(proof.agent_proof.value)
    assert not verify_agent_leaf_commitment(bytes(leaf), inner_root, aggregate)


def test_gateway_authorize():
    reg = AuthorizationRegistry()
    reg.register(mk(b"g1"))
    ok = reg.gateway_authorize(b"A", b"g1", 1)
    assert ok.allowed and ok.grant.grant_id == b"g1"
    assert ok.global_root == reg.get_global_root()
    with pytest.raises(Rejected) as exc:
        reg.gateway_authorize(b"A", b"g1", 0)
    assert exc.value.reason == "VERSION_MISMATCH"
