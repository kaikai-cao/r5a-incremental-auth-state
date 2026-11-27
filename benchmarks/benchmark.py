"""R5-A-R2 性能实验：同状态全量重建与增量更新对照。

N 定义为初始化时单个 Agent 的 ACTIVE seed 授权数量。
每个正式样本使用全新 Registry；REGISTER 后、REVOKE 后分别从**当前实际状态**
（含 tombstone）从空树全量重建，并断言重建根等于当前 Registry 根。

seed 初始化、预热均不计时也不污染正式样本。
WARMUP=5, RUNS=30, SCALES=(16,64,256,1024)。
本脚本只写 benchmarks/results_r2.csv，保留 results.csv / results_r1.csv 不覆盖。
"""

from __future__ import annotations

import csv
import hashlib
import os
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregate import (  # noqa: E402
    Capability,
    Grant,
    deserialize_grant,
    deserialize_tombstone,
    is_tombstone,
    recompute_aggregate,
    serialize_agent_leaf,
    serialize_grant,
)
from src.registry import AuthorizationRegistry  # noqa: E402
from src.smt import SMT, get_hash_count, reset_hash_count  # noqa: E402

SCALES = (16, 64, 256, 1024)
WARMUP = 5
RUNS = 30
BENCH_AGENT = b"A"

FIELDS = [
    "N",
    "run",
    "register_seconds",
    "revoke_seconds",
    "register_hashes",
    "revoke_hashes",
    "rebuild_after_register_seconds",
    "rebuild_after_revoke_seconds",
    "rebuild_after_register_hashes",
    "rebuild_after_revoke_hashes",
    "full_recompute_seconds",
    "peak_memory_mb",
    "proof_path_inner",
    "proof_path_outer",
    "global_root_after_register",
    "global_root_after_revoke",
    "root_consistency_ok",
]


def p95(values: list[float]) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * 0.95
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


class RebuildRootMismatch(RuntimeError):
    """全量重建根与当前 Registry 根不一致；必须中止该规模并保留证据。"""

    def __init__(self, stage: str, expected: bytes, actual: bytes) -> None:
        self.stage = stage
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"{stage}: expected root {expected.hex()}, rebuilt {actual.hex()}"
        )


def build_initial_state(n: int) -> AuthorizationRegistry:
    """一次性初始化，不计时；N 条 ACTIVE EXPORT / budget=0 满足冻结策略。"""
    reg = AuthorizationRegistry()
    for i in range(n):
        reg.register(
            Grant(
                f"seed-{i:06d}".encode(),
                BENCH_AGENT,
                b"ISSUER",
                Capability.EXPORT,
                0,
            )
        )
    return reg


def temp_id(index: int) -> bytes:
    return f"benchmark-temp-{index:08d}".encode()


def temp_grant(index: int) -> Grant:
    return Grant(temp_id(index), BENCH_AGENT, b"ISSUER", Capability.EXPORT, 0)


def rebuild_from_registry(registry: AuthorizationRegistry) -> tuple[bytes, int]:
    """从 Registry 的实际存储状态，从空树重建全部状态承诺。

    包含 ACTIVE 授权与 REVOKED tombstone；摘要只用 ACTIVE 记录经独立
    recompute_aggregate 重算，不读取 Registry 缓存的 Aggregate 值。
    不调用 Registry 的任何状态转换函数，也不复用当前树的缓存节点。
    """
    outer = SMT()
    active_count = 0
    for agent_tag in registry.aggregates:  # 只读 Agent 键集合，不读缓存摘要
        inner = registry.inner_smts.get(agent_tag)
        if inner is None:
            raise RebuildRootMismatch("missing_inner", b"", b"")
        rebuilt_inner = SMT()
        active: list[Grant] = []
        for path, key in inner.keys.items():
            value = inner.leaves.get(path)
            if value is None:
                raise RebuildRootMismatch("missing_leaf", b"", b"")
            if int.from_bytes(hashlib.sha256(key).digest(), "big") != path:
                raise RebuildRootMismatch("key_path_mismatch", b"", b"")
            if is_tombstone(value):
                record = deserialize_tombstone(value)
            else:
                record = deserialize_grant(value)
                active.append(record)
                active_count += 1
            if record.grant_id != key or record.agent_tag != agent_tag:
                raise RebuildRootMismatch("record_key_mismatch", b"", b"")
            rebuilt_inner.set(key, value)
        aggregate = recompute_aggregate(active)
        outer.set(agent_tag, serialize_agent_leaf(rebuilt_inner.root, aggregate))
    return outer.root, active_count


def measure_memory(n: int) -> float:
    """独立非计时通道：从空状态建树 + 5 次 UPDATE 的峰值内存。"""
    tracemalloc.start()
    try:
        reg = build_initial_state(n)
        for i in range(WARMUP):
            reg.register(temp_grant(2000 + i))
            reg.revoke(BENCH_AGENT, temp_id(2000 + i))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / (1024 * 1024)


def run_scale(n: int) -> tuple[list[dict], dict]:
    # 预热使用独立 Registry，不污染正式样本。
    warm = build_initial_state(n)
    for i in range(WARMUP):
        warm.register(temp_grant(1000 + i))
        warm.revoke(BENCH_AGENT, temp_id(1000 + i))

    samples: list[dict] = []
    reg_times: list[float] = []
    rev_times: list[float] = []
    reg_hashes: list[int] = []
    rev_hashes: list[int] = []
    rebuild_reg_times: list[float] = []
    rebuild_rev_times: list[float] = []
    rebuild_reg_hashes: list[int] = []
    rebuild_rev_hashes: list[int] = []
    oracle_times: list[float] = []
    root_register = b""
    root_revoke = b""

    def failure_row(run: int, stage: str, exc: RebuildRootMismatch, reg) -> dict:
        return {
            "N": n,
            "run": run,
            "register_seconds": "",
            "revoke_seconds": "",
            "register_hashes": "",
            "revoke_hashes": "",
            "rebuild_after_register_seconds": "",
            "rebuild_after_revoke_seconds": "",
            "rebuild_after_register_hashes": "",
            "rebuild_after_revoke_hashes": "",
            "full_recompute_seconds": "",
            "peak_memory_mb": "",
            "proof_path_inner": "",
            "proof_path_outer": "",
            "global_root_after_register": (
                reg.get_global_root().hex() if stage == "after_register" else ""
            ),
            "global_root_after_revoke": (
                reg.get_global_root().hex() if stage == "after_revoke" else ""
            ),
            "root_consistency_ok": (
                f"FAIL:{stage}:expected={exc.expected.hex()}:actual={exc.actual.hex()}"
            ),
        }

    for run in range(1, RUNS + 1):
        # 每个正式样本独立初始化，不累积 tombstone。
        reg = build_initial_state(n)
        gid = temp_id(run)

        reset_hash_count()
        t0 = time.perf_counter()
        reg.register(temp_grant(run), expected_version=reg.get_version())
        t1 = time.perf_counter()
        reg_dt = t1 - t0
        reg_h = get_hash_count()
        root_register = reg.get_global_root()

        reset_hash_count()
        t2 = time.perf_counter()
        rebuilt_reg, active_reg = rebuild_from_registry(reg)
        t3 = time.perf_counter()
        rebuild_reg_dt = t3 - t2
        rebuild_reg_h = get_hash_count()
        if rebuilt_reg != root_register or active_reg != n + 1:
            exc = RebuildRootMismatch("after_register", root_register, rebuilt_reg)
            samples.append(failure_row(run, "after_register", exc, reg))
            raise exc

        t4 = time.perf_counter()
        recompute_aggregate(reg.active_grants(BENCH_AGENT))
        t5 = time.perf_counter()
        oracle_dt = t5 - t4

        reset_hash_count()
        t6 = time.perf_counter()
        reg.revoke(BENCH_AGENT, gid, expected_version=reg.get_version())
        t7 = time.perf_counter()
        rev_dt = t7 - t6
        rev_h = get_hash_count()
        root_revoke = reg.get_global_root()

        reset_hash_count()
        t8 = time.perf_counter()
        rebuilt_rev, active_rev = rebuild_from_registry(reg)
        t9 = time.perf_counter()
        rebuild_rev_dt = t9 - t8
        rebuild_rev_h = get_hash_count()
        if rebuilt_rev != root_revoke or active_rev != n:
            exc = RebuildRootMismatch("after_revoke", root_revoke, rebuilt_rev)
            samples.append(failure_row(run, "after_revoke", exc, reg))
            raise exc

        reg_times.append(reg_dt)
        rev_times.append(rev_dt)
        reg_hashes.append(reg_h)
        rev_hashes.append(rev_h)
        rebuild_reg_times.append(rebuild_reg_dt)
        rebuild_rev_times.append(rebuild_rev_dt)
        rebuild_reg_hashes.append(rebuild_reg_h)
        rebuild_rev_hashes.append(rebuild_rev_h)
        oracle_times.append(oracle_dt)
        samples.append(
            {
                "N": n,
                "run": run,
                "register_seconds": f"{reg_dt:.9f}",
                "revoke_seconds": f"{rev_dt:.9f}",
                "register_hashes": reg_h,
                "revoke_hashes": rev_h,
                "rebuild_after_register_seconds": f"{rebuild_reg_dt:.9f}",
                "rebuild_after_revoke_seconds": f"{rebuild_rev_dt:.9f}",
                "rebuild_after_register_hashes": rebuild_reg_h,
                "rebuild_after_revoke_hashes": rebuild_rev_h,
                "full_recompute_seconds": f"{oracle_dt:.9f}",
                "peak_memory_mb": "",
                "proof_path_inner": "",
                "proof_path_outer": "",
                "global_root_after_register": root_register.hex(),
                "global_root_after_revoke": root_revoke.hex(),
                "root_consistency_ok": "OK",
            }
        )

    # 一致性复核与路径长度（不计时）
    check = build_initial_state(n)
    check.register(temp_grant(99999999))
    state = check.get_agent_state(BENCH_AGENT)
    assert state is not None
    assert state.aggregate == recompute_aggregate(check.active_grants(BENCH_AGENT))
    inner_len = len(check.prove_grant(BENCH_AGENT, b"seed-000000").siblings)
    outer_len = len(check.prove_agent(BENCH_AGENT).siblings)

    peak_mb = measure_memory(n)
    common = {
        "peak_memory_mb": f"{peak_mb:.4f}",
        "proof_path_inner": inner_len,
        "proof_path_outer": outer_len,
        "root_consistency_ok": "OK",
    }
    for label, pick in (("MEDIAN", statistics.median), ("P95", p95)):
        samples.append(
            {
                "N": n,
                "run": label,
                "register_seconds": f"{pick(reg_times):.9f}",
                "revoke_seconds": f"{pick(rev_times):.9f}",
                "register_hashes": round(pick(reg_hashes)),
                "revoke_hashes": round(pick(rev_hashes)),
                "rebuild_after_register_seconds": f"{pick(rebuild_reg_times):.9f}",
                "rebuild_after_revoke_seconds": f"{pick(rebuild_rev_times):.9f}",
                "rebuild_after_register_hashes": round(pick(rebuild_reg_hashes)),
                "rebuild_after_revoke_hashes": round(pick(rebuild_rev_hashes)),
                "full_recompute_seconds": f"{pick(oracle_times):.9f}",
                "global_root_after_register": root_register.hex(),
                "global_root_after_revoke": root_revoke.hex(),
                **common,
            }
        )

    summary = {
        "N": n,
        "median_register_s": statistics.median(reg_times),
        "p95_register_s": p95(reg_times),
        "median_revoke_s": statistics.median(rev_times),
        "p95_revoke_s": p95(rev_times),
        "median_register_hashes": statistics.median(reg_hashes),
        "median_revoke_hashes": statistics.median(rev_hashes),
        "median_rebuild_register_s": statistics.median(rebuild_reg_times),
        "p95_rebuild_register_s": p95(rebuild_reg_times),
        "median_rebuild_revoke_s": statistics.median(rebuild_rev_times),
        "p95_rebuild_revoke_s": p95(rebuild_rev_times),
        "median_rebuild_register_hashes": statistics.median(rebuild_reg_hashes),
        "median_rebuild_revoke_hashes": statistics.median(rebuild_rev_hashes),
        "median_oracle_s": statistics.median(oracle_times),
        "p95_oracle_s": p95(oracle_times),
        "peak_memory_mb": peak_mb,
        "proof_path_inner": inner_len,
        "proof_path_outer": outer_len,
        "root_after_register": root_register.hex(),
        "root_after_revoke": root_revoke.hex(),
        "ratio_register": statistics.median(rebuild_reg_times)
        / statistics.median(reg_times),
        "ratio_revoke": statistics.median(rebuild_rev_times)
        / statistics.median(rev_times),
    }
    return samples, summary


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    all_rows: list[dict] = []
    summaries: list[dict] = []
    out = ROOT / "benchmarks" / "results_r2.csv"
    try:
        for n in SCALES:
            rows, summary = run_scale(n)
            all_rows.extend(rows)
            summaries.append(summary)
            print(
                f"N={n:5d} register median={summary['median_register_s']*1e6:9.2f} us "
                f"| revoke median={summary['median_revoke_s']*1e6:9.2f} us "
                f"| rebuild(reg) median={summary['median_rebuild_register_s']*1e3:9.3f} ms "
                f"| rebuild(rev) median={summary['median_rebuild_revoke_s']*1e3:9.3f} ms "
                f"| ratio reg={summary['ratio_register']:.1f}x rev={summary['ratio_revoke']:.1f}x "
                f"| peak={summary['peak_memory_mb']:.2f} MB"
            )
    finally:
        # 即使某规模中止，也保留已采集样本与失败行。
        write_csv(all_rows, out)
        print(f"written: {out} ({len(all_rows)} rows)")


if __name__ == "__main__":
    main()
