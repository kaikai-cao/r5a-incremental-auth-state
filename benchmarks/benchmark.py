"""R5-A 性能实验：N = 16 / 64 / 256 / 1024。

每个规模：先做一次不计时的初始化，再预热 5 次，然后正式运行 30 次。
REGISTER / REVOKE 计时中不包含初始化；内存峰值在独立的非计时通道测量。
全量 Oracle 使用 aggregate.recompute_aggregate，与增量路径无代码复用。
"""

from __future__ import annotations

import csv
import os
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregate import Capability, Grant, recompute_aggregate  # noqa: E402
from src.registry import AuthorizationRegistry  # noqa: E402
from src.smt import get_hash_count, reset_hash_count  # noqa: E402

SCALES = (16, 64, 256, 1024)
WARMUP = 5
RUNS = 30
BENCH_AGENT = b"A"
TEMP_ID = b"benchmark-temp-grant"

FIELDS = [
    "N",
    "run",
    "register_seconds",
    "revoke_seconds",
    "register_hashes",
    "revoke_hashes",
    "full_recompute_seconds",
    "peak_memory_mb",
    "proof_path_inner",
    "proof_path_outer",
    "global_root",
]


def p95(values: list[float]) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * 0.95
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def build_initial_state(n: int) -> AuthorizationRegistry:
    """一次性初始化，不计时；全部为 EXPORT / budget=0 以满足冻结策略。"""
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


def temp_grant() -> Grant:
    return Grant(TEMP_ID, BENCH_AGENT, b"ISSUER", Capability.EXPORT, 0)


def measure_memory(n: int) -> float:
    """独立非计时通道：从空状态建树 + 5 次 UPDATE 的峰值内存。"""
    tracemalloc.start()
    try:
        reg = build_initial_state(n)
        for _ in range(5):
            reg.register(temp_grant())
            reg.revoke(BENCH_AGENT, TEMP_ID)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / (1024 * 1024)


def run_scale(n: int) -> tuple[list[dict], dict]:
    reg = build_initial_state(n)

    for _ in range(WARMUP):
        reg.register(temp_grant())
        reg.revoke(BENCH_AGENT, TEMP_ID)

    samples: list[dict] = []
    reg_times: list[float] = []
    rev_times: list[float] = []
    reg_hashes: list[int] = []
    rev_hashes: list[int] = []
    oracle_times: list[float] = []

    for run in range(1, RUNS + 1):
        reset_hash_count()
        t0 = time.perf_counter()
        reg.register(temp_grant(), expected_version=reg.get_version())
        t1 = time.perf_counter()
        reg_dt = t1 - t0
        reg_h = get_hash_count()

        reset_hash_count()
        t2 = time.perf_counter()
        reg.revoke(BENCH_AGENT, TEMP_ID, expected_version=reg.get_version())
        t3 = time.perf_counter()
        rev_dt = t3 - t2
        rev_h = get_hash_count()

        t4 = time.perf_counter()
        recompute_aggregate(reg.active_grants(BENCH_AGENT))
        t5 = time.perf_counter()
        oracle_dt = t5 - t4

        reg_times.append(reg_dt)
        rev_times.append(rev_dt)
        reg_hashes.append(reg_h)
        rev_hashes.append(rev_h)
        oracle_times.append(oracle_dt)
        samples.append(
            {
                "N": n,
                "run": run,
                "register_seconds": f"{reg_dt:.9f}",
                "revoke_seconds": f"{rev_dt:.9f}",
                "register_hashes": reg_h,
                "revoke_hashes": rev_h,
                "full_recompute_seconds": f"{oracle_dt:.9f}",
                "peak_memory_mb": "",
                "proof_path_inner": "",
                "proof_path_outer": "",
                "global_root": "",
            }
        )

    # 单次一致性检查（不计时）
    state = reg.get_agent_state(BENCH_AGENT)
    assert state is not None
    assert state.aggregate == recompute_aggregate(reg.active_grants(BENCH_AGENT))

    peak_mb = measure_memory(n)
    inner_len = len(reg.prove_grant(BENCH_AGENT, f"seed-000000".encode()).siblings)
    outer_len = len(reg.prove_agent(BENCH_AGENT).siblings)
    root = reg.get_global_root().hex()

    common = {
        "peak_memory_mb": f"{peak_mb:.4f}",
        "proof_path_inner": inner_len,
        "proof_path_outer": outer_len,
        "global_root": root,
    }
    for label, pick in (
        ("MEDIAN", statistics.median),
        ("P95", p95),
    ):
        samples.append(
            {
                "N": n,
                "run": label,
                "register_seconds": f"{pick(reg_times):.9f}",
                "revoke_seconds": f"{pick(rev_times):.9f}",
                "register_hashes": pick(reg_hashes),
                "revoke_hashes": pick(rev_hashes),
                "full_recompute_seconds": f"{pick(oracle_times):.9f}",
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
        "median_full_recompute_s": statistics.median(oracle_times),
        "p95_full_recompute_s": p95(oracle_times),
        "peak_memory_mb": peak_mb,
        "proof_path_inner": inner_len,
        "proof_path_outer": outer_len,
        "global_root": root,
    }
    return samples, summary


def main() -> None:
    all_rows: list[dict] = []
    summaries: list[dict] = []
    for n in SCALES:
        rows, summary = run_scale(n)
        all_rows.extend(rows)
        summaries.append(summary)
        print(f"N={n:5d} register median={summary['median_register_s']*1e6:9.2f} us "
              f"p95={summary['p95_register_s']*1e6:9.2f} us | "
              f"revoke median={summary['median_revoke_s']*1e6:9.2f} us | "
              f"oracle median={summary['median_full_recompute_s']*1e6:9.2f} us | "
              f"peak={summary['peak_memory_mb']:.2f} MB | root={summary['global_root'][:16]}")

    out = ROOT / "benchmarks" / "results.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"written: {out}")


if __name__ == "__main__":
    main()
