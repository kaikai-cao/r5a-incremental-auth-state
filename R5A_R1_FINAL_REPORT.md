# R5-A-R1 最终报告：状态语义与验证边界修复

**仓库**：`kaikai-cao/r5a-incremental-auth-state`（public）
**提交链**：`c6e0622` 框架 → `66851de` 原始实现与证据 → `9e56d84` 原始报告 →
`0b52fc1` R1 修正代码与证据 →（本报告提交）
**保留原则**：原始报告 `R5A_FINAL_REPORT.md`、`results/*.json/csv/txt`（无 `_r1` 后缀）、
`benchmarks/results.csv` 全部保留不覆盖；R1 结果一律使用 `_r1` 新文件并存。

> 本报告依据实际运行证据。所有数值来自本仓库文件，未删除失败记录，未伪造性能数据。
> 用户已核对仓库记录与源码，但**尚未在自己的环境重跑全部实验**；本报告中的运行结果是我方执行所得。

---

## 一、四项审查发现的处理结果

| 编号 | 用户发现 | 本轮处理 | 实际状态 |
| --- | --- | --- | --- |
| R5-A-01 | 撤销后 `grant_id` 可复用 | 撤销写入 tombstone 而非删除叶子；register 对 tombstone 返回 `GRANT_ID_REUSED`；T13 覆盖重放 | **已修复** |
| R5-A-02 | 独立验证器未验证 `Q = Aggregate(ActiveLeaves(R))` | 新增 `verify_leaf_set_consistency()` + T14；明确写出全量与完整性边界 | **部分修复**：能检查所给叶集合的一致性；**不扫描全部叶的完整性验证未实现** |
| R5-A-03 | `verify_transition()` 不证明状态转换；`StateProof.version` 未检查 | `verify_state_proof()` 增加 version 一致性检查 + T15 | **部分修复**：version 篡改已拒；**`S_{t+1}=Transition(S_t,e_t)` 证明仍未实现** |
| R5-A-04 | 性能对照不是端到端全量重建 | 新增独立全量重建基线（摘要+内层树+外层树+全局根），30 次 median/P95 | **已修复** |
| 文档 | README 仍写“不提前公开” | 已改为 public 状态说明 | **已修复** |

---

## 二、R5-A-01 修复细节（tombstone）

- `src/aggregate.py` 新增 `TOMBSTONE_PREFIX = b"R5A-TOMBSTONE-v1"`、
  `serialize_tombstone()` / `deserialize_tombstone()` / `is_tombstone()`。tombstone 保留
  `grant_id`、`agent_tag`、原 `capability` 与 `budget`，但 issuer 标记为 `REVOKED`。
- `src/registry.py::revoke()` 不再 `preview_set(grant_id, None)`，改为写入 tombstone；
  内层根仍承诺该叶。`revoke()` / `gateway_authorize()` 遇到 tombstone 一律 `GRANT_NOT_FOUND`。
- `register()` 先读取叶：`ACTIVE` → `DUPLICATE_GRANT_ID`，`REVOKED` → `GRANT_ID_REUSED`。
  因此“登记 → 撤销 → 原 grant_id 再登记”被拒绝。
- `active_grants()` 跳过 tombstone；聚合 `Q` 只统计 ACTIVE 记录，tombstone 不改变 `n_E/n_D/B`。
- `src/smt.py` 增加 `keys` 映射与 `prove_by_path()`，使全量诊断可枚举叶证明；
  `apply()` 删除叶时同步清理键。
- **T13** 验证：原 grant 与同 ID 不同内容的 grant 在撤销后均被拒，理由均为 `GRANT_ID_REUSED`，
  且失败前后状态快照一致，ACTIVE 集合为空、聚合回到 `(0,0,0)`。

后果：内层叶数量包含 tombstone，内存与完整重建成本随累计撤销次数增长；本轮性能实验中
每次 UPDATE 使用唯一 ID（见第四节），避免 tombstone 破坏基准。

---

## 三、R5-A-02 / R5-A-03 验证边界（不夸大）

**已实现的检查**：`verify_leaf_set_consistency(leaf_proofs, inner_root, aggregate)` 对调用方提供的
每个叶证明独立重算路径，区分 tombstone 与 ACTIVE，调用独立全量 Oracle 求和，并与承诺摘要比较。
**T14** 实测：

- 完整叶集合 + 正确摘要 → 接受；
- 篡改摘要 → 拒绝；
- 遗漏一个叶证明 → 拒绝；
- 篡改单个叶值 → 拒绝。

**明确未实现（HOLD）**：

1. 该函数要求枚举全部叶证明，本身是**全量扫描**；它不能证明「没有遗漏的叶」。
   即无法在不扫描全部授权记录的前提下验证 `Q = Aggregate(ActiveLeaves(R))`。
2. `verify_transition()` 只检查旧根/新根与外部可信检查点一致、version 递增 1；
   **不验证** `S_{t+1} = Transition(S_t, e_t)`，不验证事件合法性与聚合更新正确性。
3. 因此独立验证器仍是「路径 + 承诺 + 外部检查点」一致性验证器，不是状态转换证明验证器，
   更不是 ZK 证明。

**T15**：`verify_state_proof()` 现在检查 `StateProof.version` 存在、为 int 且等于 `version_after`；
单独把 `version` 改为 999 会被拒绝，而其余字段不变。

---

## 四、R5-A-04 性能口径修正

`benchmarks/benchmark.py` 现在包含两条独立计时路径：

- 原有：`recompute_aggregate(active_grants)`（只重算摘要）；
- 新增：`rebuild_from_scratch(n)`，从同一批授权独立构建 `Aggregate` + 内层 SMT + 外层 SMT + 全局根，
  并断言重建根与增量构建根一致。两条路径都不计入 seed 数据构造时间；每规模预热 5 次、正式 30 次。

写入 `benchmarks/results_r1.csv`（原 `results.csv` 保留）。

| N | REGISTER median / P95 (µs) | REVOKE median (µs) | 更新哈希 (reg/rev) | Oracle median (µs) | 端到端全量重建 median / P95 (ms) | 峰值内存 (MB) | 两层路径 | 结果根（前 16 hex） |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 1486.20 / 1988.79 | 1416.00 | 514 / 514 | 60.95 | 11.70 / 14.88 | 1.0380 | 256+256 | `1193860cfb6786fa` |
| 64 | 1504.00 / 1969.68 | 1476.85 | 514 / 514 | 210.25 | 48.66 / 59.12 | 3.3623 | 256+256 | `9259899e255d5ad9` |
| 256 | 1532.65 / 2482.70 | 1327.40 | 514 / 514 | 697.30 | 202.32 / 229.49 | 12.8730 | 256+256 | `0976d84172d83838` |
| 1024 | 1593.85 / 2388.57 | 1319.80 | 514 / 514 | 2885.85 | 869.81 / 912.84 | 50.4789 | 256+256 | `2a3673b0a57a9888` |

完整 30 次样本与 P95 见 CSV 的 `P95` 行。观察（实测，不外推）：

- 单次 UPDATE 耗时与哈希次数在 N=16→1024 间基本恒定（约 1.3–1.6 ms，514 次哈希）；
- 端到端全量重建从 11.70 ms (N=16) 增至 869.81 ms (N=1024)，约为单次注册的 7.9×→546×；
- 与原始 R5-A 运行的绝对耗时不可直接比较（两次独立运行、环境波动），
  可比的是各自的「随 N 变化」趋势；本轮根因 tombstone 保留而与原始根不同。
- REVOKE 哈希次数由 513 增至 514，因为写 tombstone 需要一次叶哈希。

---

## 五、测试结果与随机实验

**最终 pytest**：`python -m pytest tests/ -v > results/test_output_r1.txt` → **31 passed in 1.57s**。
其中 T1–T12 12/12，新增 T13–T15 3/3，其余为 SMT / Registry / 随机证据校验。

**10,000 次随机测试**（`results/random_test_summary_r1.json` / `random_test_events_r1.csv`，10,000 行）：

| 指标 | R1 实测 |
| --- | --- |
| seed / 实际执行 | 20261127 / 10,000 |
| 成功 / 拒绝 | 6,235 / 3,765 |
| 拒绝原因 | POLICY_VIOLATION 2,583 / VERSION_MISMATCH 790 / GRANT_NOT_FOUND 392 |
| 首个不一致操作 | `null` |
| 每步 Oracle 一致 / Φ 成立 / 拒绝后状态不变 | 全部 true |
| 最终 version | 6,235 |
| 最终全局根 | `8dbfbdefc7a87a20c207065283ec3f02185ee795994a3e238b203357eb1d55d6` |

聚合结果与原始运行相同（A `E=4,D=0,B=17`；B `E=0,D=5,B=15`；C `E=6,D=0,B=57`），
差异只在全局根：tombstone 被保留并提交。

---

## 六、裁决与研究边界

- R5-A 原始「8/8 工程验收」在新证据下成立，但必须加上 R1 修正门槛：
  grant_id 不可复用已闭合；摘要—集合一致性的**不扫描验证**与**状态转换证明**均未实现。
- **进入 Halo2：维持 NO-GO（CONDITIONAL HOLD）**。理由未变且更明确：
  1. 尚不能证明相对 FIDES / SME / EMILIA 等已有机制的增量价值；
  2. 真正值得研究的问题已从「维护增量计数器」收敛为：
     **在隐藏授权内容的前提下，证明多发行者授权集合完整性、增量状态转换正确性，以及聚合策略始终成立**；
  3. 本轮新增的边界（需要全量枚举叶才能核对摘要；转换正确性无证明）正是该问题的技术核心，
     不应通过写一个不可能通过的测试来掩盖，也不应直接把当前结构塞进 Halo2。
- 下一步：用户第二轮独立审查；若立项，应先做上述核心问题的研究价值审查与基线对照，
  而不是电路实现。本仓库继续作为查档证据，不包装为 ZKP 实现。

---

## 七、执行命令记录

```bash
python -m pytest tests/ -v                     # 修正中：30 passed
python benchmarks/benchmark.py                 # -> benchmarks/results_r1.csv
python tests/test_randomized.py                # -> results/*_r1.json/csv
python -m pytest tests/ -v > results/test_output_r1.txt 2>&1  # 31 passed
git add <精确文件列表> && git commit            # 0b52fc1
```
