# R5-A 最终报告：Incremental Authorization State Prototype

**仓库**：`kaikai-cao/r5a-incremental-auth-state`（独立实验仓库）
**执行环境**：Python 3.13.14 / CPython / Windows-11-10.0.26320-SP0 / AMD64，pytest 9.2.0
**运行时依赖**：仅 Python 标准库；无 Halo2、Rust、Noir、外部密码学库
**本地提交**：`c6e0622`（实验框架，无实现与结果）→ `66851de`（实现 + 全部证据）
**报告生成时间**：2026-11-27

> 本报告只陈述实际运行结果。所有数值来自本仓库 `results/` 与 `benchmarks/results.csv`，
> 未删除任何失败记录，未伪造性能数据。区分「已验证」「未测试」「理论判断」。

---

## 1. 实际实现的状态结构

- `Grant(grant_id, agent_tag, issuer_id, capability, budget)`，`frozen=True`；`Capability ∈ {EXPORT, DELETE}`。
  `grant_id` / `agent_tag` / `issuer_id` 非空，`budget` 限制在 uint64。
- 每个 Agent 独立持有聚合 `Aggregate(export_count, delete_count, budget_sum)`，初始 `Q0=(0,0,0)`。
  策略 `Φ(Q) = (n_E=0 ∨ n_D=0) ∧ (B≤100)` 对**每个 Agent**分别执行。
- 双层 SMT 均为固定 256 层 SHA-256 稀疏 Merkle 树：
  - 内层按 Agent 隔离，键为 `grant_id`，叶值授权记录序列化字节；
  - 外层键为 `agent_tag`，叶值 = `inner_root || serialize_aggregate(Q)`，带域分离前缀；
  - 空子树使用预计算的各层默认哈希，空叶子使用独立域分离哈希。
- 增量缓存：只保存非空叶与偏离默认值的内部节点；`preview_set()` 在新根计算阶段只重算该路径上的
  256 个父节点，`apply()` 只写缓存、不做哈希。实测每次 REGISTER 为 514 次叶/内部节点哈希，
  REVOKE 为 513 次，与授权总数 N 无关。
- 全局 `version` 从 0 起，每次成功提交 +1；CAS 仅检查 `expected_version == current_version`（单进程）。
- `gateway_authorize()` 只读校验授权存在、Agent 一致、version 匹配与策略成立，无外部副作用。

---

## 2. 关键源码说明

| 文件 | 作用 |
| --- | --- |
| `src/aggregate.py` | 冻结数据类型、确定性序列化、**独立全量 Oracle** `recompute_aggregate()`；不调用增量逻辑 |
| `src/transition.py` | **增量**状态转换 `apply_register()` / `apply_revoke()`、uint64 检查与 `Φ` 策略 |
| `src/smt.py` | 256 层增量 SMT：`preview_set()` / `apply()` / `prove()`；哈希计数用于性能实验 |
| `src/registry.py` | `AuthorizationRegistry`：REGISTER / REVOKE / CAS / GATEWAY / 状态证明构造；先只读预演、后原子提交 |
| `src/verifier.py` | 独立验证器：独立的哈希路径重算，成员/非成员证明、内外层根、聚合承诺、旧根/新根/version 一致性 |
| `tests/test_attacks.py` | T1–T12，每个用例独立构造 Registry |
| `tests/test_randomized.py` | 固定 seed 20261127 的 10,000 次随机操作、逐步 Oracle 对照、事件 CSV 与汇总 JSON |
| `benchmarks/benchmark.py` | N=16/64/256/1024，预热 5 次 + 正式 30 次，median / P95 / 峰值内存 |

**两条独立代码路径**：增量摘要由 `src/transition.py` 计算；全量 Oracle 由
`src/aggregate.py::recompute_aggregate` 从 ACTIVE 授权集合从头计数求和，二者不互相调用。

**验证器边界**：`src/verifier.py` 自行用 `hashlib.sha256` 重算路径，不读取 Registry 内部字典；
它检查的是哈希承诺与路径自洽，**不是零知识证明，也不是电路证明**。

---

## 3. 所有测试的真实结果

**最终运行**：`python -m pytest tests/ -v` → **27 passed in 1.40s**（完整输出见 `results/test_output.txt`）。

| 分组 | 结果 |
| --- | --- |
| T1–T12 指定攻击测试 | **12/12 通过** |
| SMT 增量/成员/非成员/篡改 | 6/6 通过 |
| Registry 一致性/CAS/原子性/Gateway/状态证明 | 6/6 通过 |
| 随机测试（小样本 400 次 + 证据文件校验） | 2/2 通过 |
| 合计 | 27/27 |

**保留的失败记录**：首次运行（`results/` 证据尚未生成时）为 `26 passed, 1 failed`，
失败项是 `test_randomized_evidence_file`（证据文件不存在）。生成 10,000 次随机实验证据后重跑为
27/27 通过。该失败属于测试顺序依赖，不是状态机缺陷；此处如实记录，未删除。

T1–T12 逐项：T1 混合 capability 拒绝；T2 撤销两份 EXPORT 之一后 count=1；T3 撤销不存在拒绝；
T4 同一旧 version 第二次拒绝；T5 实际篡改兄弟路径 / 聚合摘要 / 内层根 / 全局根 / version 均被拒绝；
T6 Agent B 授权不能混入 A；T7 未登记授权 Gateway 拒绝；T8 预算 80+30 拒绝；T9 非空 Genesis 拒绝；
T10 重复 grant_id 拒绝（不同 Agent 同名合法）；T11 二次 REVOKE 拒绝；T12 伪造 budget 不影响原记录与聚合摘要。

---

## 4. 随机测试结果

`python tests/test_randomized.py`，seed = **20261127**，attempts = **10,000**，实际执行 10,000 次。

| 指标 | 实测值 |
| --- | --- |
| 成功操作 | 6,235 |
| 拒绝操作 | 3,765 |
| 拒绝原因 | `POLICY_VIOLATION` 2,583 / `VERSION_MISMATCH` 790 / `GRANT_NOT_FOUND` 392 |
| 首个不一致操作编号 | `null`（无不一致） |
| 最终 version | 6,235 |
| 最终全局根 | `6ddea9f60f24f0b7254db903aa087c64933aff3fa1d434f17de4ea3e3bf8188d` |
| 每步 Oracle 一致 | true |
| 每步 Φ 成立 | true |
| 拒绝操作状态不变 | true |
| 提前终止 | false |

最终聚合：A `(E=4, D=0, B=17)`，B `(E=0, D=5, B=15)`，C `(E=6, D=0, B=57)`。
事件明细：`results/random_test_events.csv`（10,000 行，含操作、agent、grant_id、expected_version、
结果、原因、version、全局根、聚合值、Oracle 一致性、策略一致性、拒绝后状态不变标记）。
汇总：`results/random_test_summary.json`；最终状态承诺：`results/final_state.json`。

---

## 5. 性能数据

固定环境；每个规模先一次性初始化（**不计时**），预热 5 次，正式 30 次；内存峰值在独立非计时通道
（tracemalloc，从空状态建树 + 5 次更新）测量。完整 30 次样本 + MEDIAN/P95 行见 `benchmarks/results.csv`。

| N | REGISTER median / P95 (µs) | REVOKE median / P95 (µs) | 更新哈希次数 (reg / rev) | Oracle median / P95 (µs) | 峰值内存 (MB) | 两层证明路径长度 | 结果根（前 16 hex） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 1053.35 / 1731.55 | 1105.75 / 1384.79 | 514 / 513 | 48.50 / 57.28 | 0.9010 | 256 + 256 | `95443fda9c416267` |
| 64 | 1059.80 / 1558.20 | 1079.30 / 1514.03 | 514 / 513 | 163.95 / 334.97 | 3.2229 | 256 + 256 | `3d466aef6005e2bd` |
| 256 | 1063.75 / 1384.53 | 1076.15 / 1561.32 | 514 / 513 | 623.90 / 1313.26 | 12.7202 | 256 + 256 | `c478b300cd90a84d` |
| 1024 | 1074.85 / 2089.83 | 1085.65 / 1563.74 | 514 / 513 | 2454.50 / 3463.92 | 50.2687 | 256 + 256 | `0404f3f7e931b6e6` |

观察（实测，非外推）：REGISTER / REVOKE 耗时与哈希次数在 N=16→1024 间基本恒定，符合
「只更新 256 层路径、不扫描全部授权」的实现约束；Oracle 全量重算耗时随 N 线性增长；
内存峰值随 N 增长（缓存节点与叶子字典）。P95 有波动，未做运行环境隔离或性能调优，
不声称任何生产性能或普遍性能优势。

---

## 6. 与全量 Oracle 的比较

- 10,000 次操作后，每一步对 A/B/C 三个 Agent 分别比较
  `registry.aggregate == recompute_aggregate(active_grants(agent))`，全部一致。
- 策略 `Φ` 在每步对三个 Agent 均成立；拒绝操作的指纹（version + 全局根 + 各 Agent 聚合）与操作前一致。
- 两条路径互相独立：增量路径为 `src/transition.py::apply_register / apply_revoke`；
  Oracle 为 `src/aggregate.py::recompute_aggregate`，后者遍历 ACTIVE 授权集合重新计数求和，
  不读取缓存摘要，也不调用增量函数。
- SMT 层也做了交叉检查：同一批叶子按不同插入顺序构建，根哈希一致；成员与非成员路径均被
  独立验证器接受；篡改兄弟节点、叶值、根均被拒绝。

---

## 7. 未实现功能

- Halo2 / Rust / Noir 电路；任何 ZKP 证明、约束系统、可信设置、证明大小与验证成本测量。
- 真实发行者签名与签名验证；`issuer_id` 仅为标签。
- 分布式 CAS、共识、多节点线性一致性、跨存储原子性、exactly-once。
- 持久化存储、崩溃恢复、并发控制/锁。
- 真实业务授权策略；`Φ` 是为实验冻结的人造不变量。
- 哈希碰撞的显式处理（依赖 SHA-256 抗碰撞性假设）。

---

## 8. 发现的安全问题与诚实边界

以下问题均为**已知范围外或已识别局限**，不是隐蔽漏洞；按严重性列出：

1. **身份真实性缺失**：`issuer_id` 未经签名验证，调用方可任意填写。原型层面无法防止伪造发行者标签。
2. **并发 TOCTOU**：`_check_cas()` 与 `apply()` 之间没有锁。单线程顺序执行下测试全部通过；
   真实并发调用下可能出现两个更新同时读到同一 version。本阶段**未测试**并发场景。
3. **状态证明非自包含**：`verify_state_proof()` 的旧根检查依赖外部提供的 `trusted_old_root`。
   若该可信根本身被伪造，验证器无法独立发现。它不是电路证明，也没有证明「新根由旧根正确转换而来」。
4. **非成员证明边界**：非成员证明只证明 `H(key)` 对应叶为空，不显式处理 SHA-256 碰撞；
   当叶值存在时才校验记录内 `grant_id` / `agent_tag` 与查询键一致。
5. **策略语义人为**：`Φ` 禁止同一 Agent 同时存在 EXPORT 与 DELETE，且预算上限 100。
   这是判定性测试不变量，不代表任何真实授权系统的安全策略。
6. **性能声明受限**：数据来自未优化的 CPython 单进程原型，P95 波动明显；不得外推为生产性能。
7. **测试顺序依赖**：证据文件未生成时 `test_randomized_evidence_file` 会失败（已如实记录于第 3 节）。

---

## 9. 是否满足进入 Halo2 阶段的条件

**R5-A 工程验收门槛：8/8 通过**（12/12 攻击测试；10,000 次随机操作；每步摘要与 Oracle 一致；
SMT 正反路径正确；失败操作状态不变；增量更新不扫描全部记录；4 档性能记录完整；独立验证器拒绝篡改）。

**进入 Halo2 阶段的研究判定：当前证据下 NO-GO（CONDITIONAL HOLD）**。

理由：

1. 本原型回答的是「状态机与增量数据结构是否正确」，**没有回答「相对已有机制的额外价值」**；
   没有与 FIDES / SME / 动态污点 / 静态 IFC / ZK-IFC 等基线做对比。
2. 没有任何电路、约束系统、证明大小、验证成本或可信设置测量，因此没有支持 Halo2 实现决策的工程量数据。
3. 真实发行者签名、多节点一致性、持久化均未实现；单进程 CAS 不能作为分布式一致性证据。
4. `Φ` 是人为不变量，不能把「在该不变量下保持一致」解释为真实系统的安全保证。
5. 独立验证器只是哈希验证，不能被描述为零知识安全性证据。

**建议的下一步**：先做研究价值审查（基线与增量价值、必要性与可证性质），由用户进行第二轮独立审查，
重点复核增量状态与全量集合的一致性证据以及研究增量；之后再决定是否立项 Halo2。
本仓库在此阶段冻结为查档证据，不包装为 ZKP 实现。

---

## 附：执行命令记录

```bash
git init -b main
python -m pytest tests/ -v                 # 首次：26 passed, 1 failed（证据未生成）
python tests/test_randomized.py            # 10,000 次，生成 results/random_test_*.json/csv 与 final_state.json
python benchmarks/benchmark.py             # 生成 benchmarks/results.csv
python -m pytest tests/ -v > results/test_output.txt 2>&1   # 最终：27 passed
git add <精确文件列表> && git commit         # c6e0622、66851de
```
