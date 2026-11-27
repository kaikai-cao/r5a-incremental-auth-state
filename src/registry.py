"""R5-A 授权状态机：REGISTER / REVOKE / CAS / GATEWAY。

原子性策略：所有校验与新根计算都在**只读预演**阶段完成；只有通过全部检查后
才调用 SMT.apply 提交缓存变更并递增 version。失败路径不触碰任何状态。
"""

from __future__ import annotations

from dataclasses import dataclass

from .aggregate import (
    ZERO_AGGREGATE,
    Aggregate,
    Grant,
    Rejected,
    deserialize_agent_leaf,
    deserialize_grant,
    serialize_agent_leaf,
    serialize_grant,
    validate_grant,
)
from .smt import EMPTY_HASHES, SMT, SMTProof
from .transition import apply_register, apply_revoke, policy_holds
from .verifier import StateProof


@dataclass(frozen=True)
class AgentState:
    agent_tag: bytes
    inner_root: bytes
    aggregate: Aggregate
    proof: SMTProof


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    reason: str
    grant: Grant | None
    version: int
    global_root: bytes


class AuthorizationRegistry:
    def __init__(self, genesis: Aggregate | None = None) -> None:
        if genesis is not None and (
            not isinstance(genesis, Aggregate) or genesis != ZERO_AGGREGATE
        ):
            raise Rejected("INVALID_GENESIS", f"non-empty genesis rejected: {genesis}")
        self.global_smt = SMT()
        self.inner_smts: dict[bytes, SMT] = {}
        self.aggregates: dict[bytes, Aggregate] = {}
        self.version = 0
        self._last_transition = (
            EMPTY_HASHES[0],
            EMPTY_HASHES[0],
            0,
            0,
        )

    # ---------- 只读查询 ----------

    def get_version(self) -> int:
        return self.version

    def get_global_root(self) -> bytes:
        return self.global_smt.root

    def get_agent_state(self, agent_tag: bytes) -> AgentState | None:
        if agent_tag not in self.aggregates:
            return None
        leaf = self.global_smt.get(agent_tag)
        if leaf is None:
            return None
        inner_root, agg = deserialize_agent_leaf(leaf)
        return AgentState(
            agent_tag=agent_tag,
            inner_root=inner_root,
            aggregate=agg,
            proof=self.global_smt.prove(agent_tag),
        )

    def active_grants(self, agent_tag: bytes) -> tuple[Grant, ...]:
        """仅供测试与 Oracle 使用：按 Agent 读取当前 ACTIVE 授权。"""
        inner = self.inner_smts.get(agent_tag)
        if inner is None:
            return tuple()
        return tuple(deserialize_grant(value) for value in inner.leaves.values())

    def prove_agent(self, agent_tag: bytes) -> SMTProof:
        return self.global_smt.prove(agent_tag)

    def prove_grant(self, agent_tag: bytes, grant_id: bytes) -> SMTProof:
        inner = self.inner_smts.get(agent_tag)
        if inner is None:
            raise Rejected("AGENT_NOT_FOUND", "agent has no inner tree")
        return inner.prove(grant_id)

    def build_state_proof(self, agent_tag: bytes, grant_id: bytes) -> StateProof:
        agent_proof = self.prove_agent(agent_tag)
        if agent_proof.value is None:
            raise Rejected("AGENT_NOT_FOUND", "agent not committed in global SMT")
        inner_root, agg = deserialize_agent_leaf(agent_proof.value)
        old_root, new_root, v_before, v_after = self._last_transition
        return StateProof(
            agent_tag=agent_tag,
            grant_id=grant_id,
            version=self.version,
            global_root=self.get_global_root(),
            agent_proof=agent_proof,
            inner_proof=self.prove_grant(agent_tag, grant_id),
            old_global_root=old_root,
            new_global_root=new_root,
            version_before=v_before,
            version_after=v_after,
            aggregate=agg,
        )

    def state_snapshot(self) -> dict:
        """用于失败原子性检查的完整状态快照。"""
        return {
            "version": self.version,
            "global_root": self.get_global_root(),
            "aggregates": dict(self.aggregates),
            "inner_roots": {tag: tree.root for tag, tree in self.inner_smts.items()},
            "agent_leaves": {
                tag: self.global_smt.get(tag) for tag in self.aggregates
            },
            "grant_leaves": {
                tag: dict(tree.leaves) for tag, tree in self.inner_smts.items()
            },
        }

    # ---------- 内部辅助 ----------

    def _check_cas(self, expected_version: int | None) -> None:
        if expected_version is None:
            return
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            raise Rejected("VERSION_MISMATCH", "expected_version is not int")
        if expected_version != self.version:
            raise Rejected(
                "VERSION_MISMATCH",
                f"expected {expected_version}, current {self.version}",
            )

    def _finish(self, old_root: bytes, new_root: bytes, version_before: int) -> None:
        self._last_transition = (
            old_root,
            new_root,
            version_before,
            version_before + 1,
        )
        self.version = version_before + 1

    def _commit_leaf(
        self,
        agent: bytes,
        inner: SMT,
        inner_preview,
        outer_preview,
        new_agg: Aggregate,
    ) -> bytes:
        old_root = self.get_global_root()
        inner.apply(inner_preview)
        if agent not in self.inner_smts:
            self.inner_smts[agent] = inner
        self.global_smt.apply(outer_preview)
        self.aggregates[agent] = new_agg
        self._finish(old_root, self.get_global_root(), self.version)
        return self.get_global_root()

    # ---------- 状态转换 ----------

    def register(self, grant: Grant, expected_version: int | None = None) -> bytes:
        validate_grant(grant)
        self._check_cas(expected_version)

        agent = grant.agent_tag
        inner = self.inner_smts.get(agent)
        if inner is None:
            inner = SMT()
        if inner.contains(grant.grant_id):
            raise Rejected("DUPLICATE_GRANT_ID", "grant_id already active in agent")

        current_agg = self.aggregates.get(agent, ZERO_AGGREGATE)
        new_agg = apply_register(current_agg, grant.capability, grant.budget)

        grant_bytes = serialize_grant(grant)
        inner_preview = inner.preview_set(grant.grant_id, grant_bytes)
        new_agent_leaf = serialize_agent_leaf(inner_preview.new_root, new_agg)
        outer_preview = self.global_smt.preview_set(agent, new_agent_leaf)

        return self._commit_leaf(agent, inner, inner_preview, outer_preview, new_agg)

    def revoke(
        self,
        agent_tag: bytes,
        grant_id: bytes,
        expected_version: int | None = None,
    ) -> bytes:
        if not isinstance(agent_tag, bytes) or not agent_tag:
            raise Rejected("INVALID_GRANT", "agent_tag must be non-empty bytes")
        if not isinstance(grant_id, bytes) or not grant_id:
            raise Rejected("INVALID_GRANT", "grant_id must be non-empty bytes")
        self._check_cas(expected_version)

        inner = self.inner_smts.get(agent_tag)
        if inner is None:
            raise Rejected("GRANT_NOT_FOUND", "agent has no active grants")
        grant_bytes = inner.get(grant_id)
        if grant_bytes is None:
            raise Rejected("GRANT_NOT_FOUND", "grant_id not active in agent")

        # 能力/预算必须从 Registry 存储记录读取，绝不接收调用方提供的字段。
        grant = deserialize_grant(grant_bytes)
        if grant.agent_tag != agent_tag:
            raise Rejected("GRANT_NOT_FOUND", "grant belongs to a different agent")

        current_agg = self.aggregates[agent_tag]
        new_agg = apply_revoke(current_agg, grant.capability, grant.budget)

        inner_preview = inner.preview_set(grant_id, None)
        new_agent_leaf = serialize_agent_leaf(inner_preview.new_root, new_agg)
        outer_preview = self.global_smt.preview_set(agent_tag, new_agent_leaf)

        return self._commit_leaf(
            agent_tag, inner, inner_preview, outer_preview, new_agg
        )

    def gateway_authorize(
        self, agent_tag: bytes, grant_id: bytes, expected_version: int
    ) -> GatewayDecision:
        self._check_cas(expected_version)
        inner = self.inner_smts.get(agent_tag)
        if inner is None:
            raise Rejected("GRANT_NOT_FOUND", "agent has no active grants")
        grant_bytes = inner.get(grant_id)
        if grant_bytes is None:
            raise Rejected("GRANT_NOT_FOUND", "grant_id not active")
        grant = deserialize_grant(grant_bytes)
        if grant.agent_tag != agent_tag:
            raise Rejected("GRANT_NOT_FOUND", "grant belongs to a different agent")
        agg = self.aggregates[agent_tag]
        if not policy_holds(agg):
            raise Rejected("POLICY_VIOLATION", "agent policy no longer holds")
        return GatewayDecision(
            allowed=True,
            reason="OK",
            grant=grant,
            version=self.version,
            global_root=self.get_global_root(),
        )
