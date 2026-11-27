# R5-A: Incremental Authorization State Prototype

独立实验仓库。`kaikai-cao/r5a-incremental-auth-state`。

## 定位

本仓库只做一件事：在 **纯 Python** 中验证「双层 Sparse Merkle Tree + 增量聚合摘要」能否正确维护多 Agent 的全局授权状态。

本仓库 **不是** ZKP 实现，也不是 Halo2 / Rust / Noir 项目。第一阶段只验证状态机和增量数据结构。

## 冻结边界（不得越界）

- 不修改 `agent-exec-binding-mvp`、`Orchard`、`Sapling` 或任何其他现有仓库。
- 不引入 Halo2、Rust、Noir 或外部密码学库；运行时只使用 Python 标准库。
- 不实现真实发行者签名；`issuer_id` 只是标签，不是经过验证的签名主体。
- 不把独立哈希验证描述成零知识证明。
- 仓库当前为 **public**（2026-11-27 按用户要求公开，便于外部核查）；初始曾为 private。
- 不删除失败案例，不伪造性能数据。

## 目录结构

```
r5a-incremental-auth-state/
├── README.md
├── requirements.txt
├── environment.txt
├── .gitignore
├── src/
│   ├── smt.py            256 层 SHA-256 稀疏 Merkle 树（增量缓存路径）
│   ├── registry.py       授权状态机（REGISTER / REVOKE / CAS / GATEWAY）
│   ├── aggregate.py      Grant / Capability / Aggregate / 独立全量 Oracle
│   ├── transition.py     状态转换与策略 Φ
│   └── verifier.py       独立 SMT / 状态承诺 / 转换验证器
├── tests/
│   ├── test_smt.py
│   ├── test_registry.py
│   ├── test_attacks.py   T1–T15
│   └── test_randomized.py
├── benchmarks/
│   ├── benchmark.py
│   ├── results.csv          原始证据（保留）
│   └── results_r1.csv       R1：加入端到端全量重建基线
├── results/
│   ├── test_output.txt                    原始证据（保留）
│   ├── random_test_summary.json           原始证据（保留）
│   ├── random_test_events.csv             原始证据（保留）
│   ├── final_state.json                   原始证据（保留）
│   ├── test_output_r1.txt                 R1 新证据
│   ├── random_test_summary_r1.json         R1 新证据
│   ├── random_test_events_r1.csv           R1 新证据
│   └── final_state_r1.json                 R1 新证据
├── docs/
│   ├── state_model.md
│   ├── security_assumptions.md
│   └── limitations.md
├── R5A_FINAL_REPORT.md        原始报告（保留）
└── R5A_R1_FINAL_REPORT.md     R1 修正后报告
```

## 冻结状态模型（摘要）

- `Grant(grant_id, agent_tag, issuer_id, capability, budget)`，`capability ∈ {EXPORT, DELETE}`。
- 每个 Agent 维护自己的聚合 `Q = (n_E, n_D, B)`，初始 `Q0 = (0,0,0)`。
- 策略 `Φ(Q) = (n_E = 0 ∨ n_D = 0) ∧ (B ≤ 100)`；对 **每个 Agent** 分别成立。
- 所有整数为 uint64 语义。
- 外层 SMT 叶承诺 `H(inner_root, aggregate)`；内层 SMT 叶承诺授权记录或撤销 tombstone。
- **R5-A-R1**：撤销保留 tombstone，`grant_id` 在同一 Agent 内登记后永不复用；聚合只计 ACTIVE 记录。
- 每次叶子修改最多更新 256 个父节点，禁止从全部叶子重建整棵树。
- CAS 只检查单进程内的 `expected_version == current_version`；不声称分布式共识或线性一致性。

详细定义见 `docs/state_model.md`。

## 验收门槛

| 指标 | 通过条件 |
| --- | --- |
| 指定攻击测试 | 12/12 通过 |
| 随机操作 | 10,000 次（seed = 20261127） |
| 摘要一致性 | 每次操作均与独立全量 Oracle 相同 |
| SMT 路径 | 成员 / 非成员证明均正确 |
| 原子性 | 失败操作状态不变 |
| 增量更新 | 不扫描全部授权记录 |
| 性能记录 | N = 16 / 64 / 256 / 1024 完整 |
| 独立验证器 | 篡改输入能被拒绝 |

## 当前提交状态

- `c6e0622`：仅实验框架。
- `66851de`：原始实现与证据（保留，不覆盖）。
- `9e56d84`：原始最终报告。
- R1 修正提交见 `R5A_R1_FINAL_REPORT.md`；原始报告与原始证据文件均保留用于对照。

## 运行方式

```bash
python -m pytest tests/ -v > results/test_output_r1.txt 2>&1
python tests/test_randomized.py          # 写入 *_r1.*，不覆盖原始证据
python benchmarks/benchmark.py           # 写入 benchmarks/results_r1.csv
```
