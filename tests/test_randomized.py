"""固定种子 10,000 次随机一致性测试 + 独立全量 Oracle 对照。

可直接运行：
    python tests/test_randomized.py
也可由 pytest 收集（小样本运行 + 证据文件校验）。
"""

from __future__ import annotations

import csv
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregate import (  # noqa: E402
    Aggregate,
    Capability,
    Grant,
    Rejected,
    recompute_aggregate,
)
from src.registry import AuthorizationRegistry  # noqa: E402
from src.transition import policy_holds  # noqa: E402

SEED = 20261127
AGENTS = (b"A", b"B", b"C")
RESULTS = ROOT / "results"

EVENT_FIELDS = [
    "op_index",
    "operation",
    "agent",
    "grant_id",
    "capability",
    "budget",
    "expected_version",
    "version_before",
    "result",
    "reason",
    "version_after",
    "global_root",
    "aggregate_export",
    "aggregate_delete",
    "aggregate_budget",
    "oracle_match",
    "policy_ok",
    "state_unchanged_on_reject",
]


def _fingerprint(reg: AuthorizationRegistry):
    """轻量状态指纹：版本 + 全局根（承诺全部叶）+ 各 Agent 聚合。"""
    return (
        reg.get_version(),
        reg.get_global_root(),
        tuple(sorted((tag, agg) for tag, agg in reg.aggregates.items())),
    )


def run_random_test(
    attempts: int,
    seed: int = SEED,
    emit_files: bool = False,
) -> tuple[dict, list[dict]]:
    rng = random.Random(seed)
    reg = AuthorizationRegistry()

    events: list[dict] = []
    rejection_reasons: dict[str, int] = {}
    successes = 0
    rejects = 0
    oracle_ok = True
    policy_ok = True
    atomic_ok = True
    first_inconsistent: int | None = None

    for index in range(attempts):
        agent = rng.choice(AGENTS)
        current_version = reg.get_version()
        expected_version = (
            max(0, current_version - 1)
            if rng.random() < 0.08
            else current_version
        )
        operation = "REGISTER" if rng.random() < 0.62 else "REVOKE"
        grant_id = b""
        capability = ""
        budget = ""
        before = _fingerprint(reg)
        reason = ""
        unchanged_on_reject = True

        try:
            if operation == "REGISTER":
                grant_id = f"g{index:06d}".encode()
                cap = rng.choice([Capability.EXPORT, Capability.DELETE])
                budget = rng.randint(0, 15)
                capability = cap.name
                reg.register(
                    Grant(grant_id, agent, b"ISSUER", cap, budget),
                    expected_version=expected_version,
                )
            else:
                active = reg.active_grants(agent)
                grant_id = rng.choice(active).grant_id if active else b"missing-grant"
                reg.revoke(agent, grant_id, expected_version=expected_version)
            result = "ACCEPT"
            successes += 1
        except Rejected as exc:
            result = "REJECT"
            reason = exc.reason
            rejects += 1
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
            unchanged_on_reject = _fingerprint(reg) == before
            if not unchanged_on_reject:
                atomic_ok = False

        step_oracle = True
        step_policy = True
        for tag in AGENTS:
            state = reg.get_agent_state(tag)
            incremental = state.aggregate if state else Aggregate(0, 0, 0)
            oracle = recompute_aggregate(reg.active_grants(tag))
            if incremental != oracle:
                step_oracle = False
                oracle_ok = False
            if not policy_holds(incremental):
                step_policy = False
                policy_ok = False

        if first_inconsistent is None and (
            not step_oracle or not step_policy or not unchanged_on_reject
        ):
            first_inconsistent = index

        state = reg.get_agent_state(agent)
        agg = state.aggregate if state else Aggregate(0, 0, 0)
        events.append(
            {
                "op_index": index,
                "operation": operation,
                "agent": agent.decode(),
                "grant_id": grant_id.decode(errors="replace"),
                "capability": capability,
                "budget": budget,
                "expected_version": expected_version,
                "version_before": before[0],
                "result": result,
                "reason": reason,
                "version_after": reg.get_version(),
                "global_root": reg.get_global_root().hex(),
                "aggregate_export": agg.export_count,
                "aggregate_delete": agg.delete_count,
                "aggregate_budget": agg.budget_sum,
                "oracle_match": step_oracle,
                "policy_ok": step_policy,
                "state_unchanged_on_reject": unchanged_on_reject,
            }
        )
        if first_inconsistent is not None:
            # 立即停止，保留触发不一致的精确事件作为证据。
            break

    summary = {
        "seed": seed,
        "attempts": attempts,
        "executed_operations": len(events),
        "successful_operations": successes,
        "rejected_operations": rejects,
        "rejection_reasons": dict(sorted(rejection_reasons.items())),
        "first_inconsistent_op": first_inconsistent,
        "final_version": reg.get_version(),
        "final_global_root": reg.get_global_root().hex(),
        "final_aggregates": {
            tag.decode(): {
                "export_count": (
                    reg.get_agent_state(tag).aggregate.export_count
                    if reg.get_agent_state(tag)
                    else 0
                ),
                "delete_count": (
                    reg.get_agent_state(tag).aggregate.delete_count
                    if reg.get_agent_state(tag)
                    else 0
                ),
                "budget_sum": (
                    reg.get_agent_state(tag).aggregate.budget_sum
                    if reg.get_agent_state(tag)
                    else 0
                ),
                "active_grants": len(reg.active_grants(tag)),
            }
            for tag in AGENTS
        },
        "incremental_path": "src.transition.apply_register / apply_revoke",
        "oracle_path": "src.aggregate.recompute_aggregate (independent full scan)",
        "all_oracle_checks_passed": oracle_ok,
        "all_policy_checks_passed": policy_ok,
        "all_rejected_ops_state_unchanged": atomic_ok,
        "stopped_early_due_to_inconsistency": first_inconsistent is not None,
    }

    if emit_files:
        RESULTS.mkdir(parents=True, exist_ok=True)
        with (RESULTS / "random_test_events.csv").open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=EVENT_FIELDS)
            writer.writeheader()
            writer.writerows(events)
        with (RESULTS / "random_test_summary.json").open("w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        final_state = {
            "version": reg.get_version(),
            "global_root": reg.get_global_root().hex(),
            "agents": {
                tag.decode(): {
                    "inner_root": (
                        reg.get_agent_state(tag).inner_root.hex()
                        if reg.get_agent_state(tag)
                        else None
                    ),
                    "aggregate": summary["final_aggregates"][tag.decode()],
                    "grant_ids": [
                        grant.grant_id.hex() for grant in reg.active_grants(tag)
                    ],
                }
                for tag in AGENTS
            },
            "note": "Synthetic experiment state. No real issuer signatures.",
        }
        with (RESULTS / "final_state.json").open("w", encoding="utf-8") as fh:
            json.dump(final_state, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    return summary, events


def test_randomized_small_run():
    summary, events = run_random_test(attempts=400, seed=SEED, emit_files=False)
    assert len(events) == 400
    assert summary["successful_operations"] + summary["rejected_operations"] == 400
    assert summary["first_inconsistent_op"] is None
    assert summary["all_oracle_checks_passed"]
    assert summary["all_policy_checks_passed"]
    assert summary["all_rejected_ops_state_unchanged"]


def test_randomized_evidence_file():
    summary_path = RESULTS / "random_test_summary.json"
    assert summary_path.exists(), "请先运行 python tests/test_randomized.py 生成证据"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["seed"] == SEED
    assert summary["attempts"] == 10000
    assert summary["executed_operations"] == 10000
    assert summary["successful_operations"] + summary["rejected_operations"] == 10000
    assert summary["first_inconsistent_op"] is None
    assert summary["all_oracle_checks_passed"]
    assert summary["all_policy_checks_passed"]
    assert summary["all_rejected_ops_state_unchanged"]
    with (RESULTS / "random_test_events.csv").open(encoding="utf-8") as fh:
        assert sum(1 for _ in csv.DictReader(fh)) == 10000


if __name__ == "__main__":
    result, _ = run_random_test(attempts=10000, seed=SEED, emit_files=True)
    print(json.dumps(result, indent=2, ensure_ascii=False))
