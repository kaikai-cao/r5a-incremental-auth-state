"""R5-A 增量状态转换与策略 Φ。

本模块只实现**增量**转换：由旧 Aggregate 与单条授权计算新 Aggregate。
全量重算在 aggregate.recompute_aggregate 中，二者代码路径互不复用。
"""

from __future__ import annotations

from .aggregate import (
    BUDGET_CAP,
    UINT64_MAX,
    Aggregate,
    Capability,
    Rejected,
)


def policy_holds(agg: Aggregate) -> bool:
    """Φ(Q) = (n_E = 0 ∨ n_D = 0) ∧ (B ≤ 100)。"""
    return (agg.export_count == 0 or agg.delete_count == 0) and (
        agg.budget_sum <= BUDGET_CAP
    )


def check_uint64(agg: Aggregate) -> None:
    for name in ("export_count", "delete_count", "budget_sum"):
        value = getattr(agg, name)
        if value < 0:
            raise Rejected("UNDERFLOW", f"{name} below zero")
        if value > UINT64_MAX:
            raise Rejected("AGGREGATE_OVERFLOW", f"{name} exceeds uint64")


def apply_register(agg: Aggregate, capability: Capability, budget: int) -> Aggregate:
    """REGISTER 增量更新；带 uint64 范围与策略检查。"""
    if not isinstance(capability, Capability):
        raise Rejected("INVALID_GRANT", "bad capability")
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise Rejected("INVALID_GRANT", "bad budget")
    if budget < 0 or budget > UINT64_MAX:
        raise Rejected("INVALID_GRANT", "budget out of uint64 range")

    if capability is Capability.EXPORT:
        new = Aggregate(agg.export_count + 1, agg.delete_count, agg.budget_sum + budget)
    else:
        new = Aggregate(agg.export_count, agg.delete_count + 1, agg.budget_sum + budget)

    check_uint64(new)
    if not policy_holds(new):
        raise Rejected("POLICY_VIOLATION", f"register violates Phi: {new}")
    return new


def apply_revoke(agg: Aggregate, capability: Capability, budget: int) -> Aggregate:
    """REVOKE 增量更新；禁止计数器下溢并检查策略。"""
    if not isinstance(capability, Capability):
        raise Rejected("INVALID_GRANT", "bad capability")
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise Rejected("INVALID_GRANT", "bad budget")
    if budget < 0 or budget > UINT64_MAX:
        raise Rejected("INVALID_GRANT", "budget out of uint64 range")

    if capability is Capability.EXPORT:
        if agg.export_count < 1 or agg.budget_sum < budget:
            raise Rejected("UNDERFLOW", "export revoke would underflow")
        new = Aggregate(agg.export_count - 1, agg.delete_count, agg.budget_sum - budget)
    else:
        if agg.delete_count < 1 or agg.budget_sum < budget:
            raise Rejected("UNDERFLOW", "delete revoke would underflow")
        new = Aggregate(agg.export_count, agg.delete_count - 1, agg.budget_sum - budget)

    check_uint64(new)
    if not policy_holds(new):
        raise Rejected("POLICY_VIOLATION", f"revoke violates Phi: {new}")
    return new
