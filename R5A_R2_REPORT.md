# R5-A-R2 最终审计与实验报告

**任务**：验证器边界加固与同状态性能基准修正
**仓库**：`kaikai-cao/r5a-incremental-auth-state`
**性质**：Python 参考原型的工程修正轮次；不实现 ZKP，不进入 Halo2。

---

## 8.1 版本与提交

| 项目 | 值 |
| --- | --- |
| R2 基线 SHA | `3b54b68c7660f9e457dd986189085446fcbe17c5` |
| 基线核验 | 本地 HEAD = 远端 `main` = 基线；工作区 clean；本地路径 `D:\Research\r5a-incremental-auth-state` |
| 新分支 | `r5a-r2-hardening`（从基线创建，未合并/更新 `main`） |
| 代码与测试提交 SHA | `5c49173f0f067d95e827aecb6785139b6102b356` |
| 最终报告提交 SHA | 本报告为第二笔提交；实际 SHA 见最终推送核验与回传 |
| 工作区状态 | 第一笔提交后 clean；本报告提交后再次核验 |

门禁检查在执行前完成：基线 SHA、远端 `main` SHA、工作区 clean、仓库路径四项全部符合；分支创建时 `r5a-r2-hardening` 不存在，无覆盖或删除操作。

**保留不覆盖**：`R5A_FINAL_REPORT.md`、`R5A_R1_FINAL_REPORT.md`、原始与 R1 的 `results/*`、`benchmarks/results.csv`、`benchmarks/results_r1.csv` 均未修改。R2 新证据使用 `_r2` 后缀。

**冻结范围**：只修改 `src/verifier.py`、`benchmarks/benchmark.py`、`tests/test_attacks.py`、`tests/test_registry.py`、`README.md`、`docs/security_assumptions.md`、`docs/limitations.md`；新增 `tests/test_attacks_r2.py`、`benchmarks/results_r2.csv`、`results/test_output_r2.txt`、`R5A_R2_REPORT.md`。未引入 Halo2/Rust/Noir、Poseidon/Pallas、真实签名、分布式 CAS/共识、ZK 完整性证明；未修改策略 Φ；未修改 Registry 状态转换、随机操作生成或聚合规则。

---

## 8.2 T16：重复叶证明防护

### 实现

`src/verifier.py::verify_leaf_set_consistency()` 在聚合计算前新增三层检查：

1. 每个 `proof.key` 必须是非空 `bytes`；非 bytes（如 `str`）或空 key 直接返回 `False`；
2. `seen_keys` 拒绝重复 key；
3. `seen_path_ids` 拒绝重复 `path_id = hashlib.sha256(proof.key).digest()`。

原有能力保留：逐条独立验证 SMT 路径、授权记录反序列化、墓碑反序列化、`grant_id` 与证明 key 一致、对 ACTIVE 授权经 `recompute_aggregate()` 全量重算并对照 `committed_aggregate`。验证器不读取 Registry 内部状态替代对证明字节的检查。

重复路径标识检查是防御性检查：在 SHA-256 抗碰撞假设下，不同 key 不会产生相同 `path_id`，因此没有可构造的真实碰撞样例；代码层已实现，未伪造碰撞测试。

### 测试结果

| 用例 | 结果 |
| --- | --- |
| T16-A 唯一叶集合（两份不同授权） | 通过 |
| T16-B 完全重复证明 `[p1, p1, p2]` | 通过（拒绝） |
| T16-C 不相邻重复 `[p1, p2, p3, p1]` 与 `[p3, p1, p2, p3]` | 通过（拒绝） |
| T16-D 遗漏 ACTIVE 叶 / 摘要被篡改 | 通过（拒绝） |
| T16-E 遗漏 tombstone 的边界记录 | 通过（限制演示，见下） |
| T16-F 空 key 与非 bytes key | 通过（拒绝） |

**T16-E 已知限制（明确记录，未修复）**：登记 `g1` → 撤销为 tombstone → 登记 `g2` 后，仅提交 `g2` 的有效成员证明、不提交 `g1` 的墓碑证明，当前验证器仍返回 `True`。原因是函数只能检查「已提供叶集合」的聚合是否等于承诺摘要，无法证明集合完整（没有未提供的 tombstone 或其他不影响聚合的叶）。该测试断言当前行为作为限制基线；完整集合证明**未实现**，不得把重复证明防护误认为完整集合证明。

---

## 8.3 T17：版本字段绑定可信检查点

### 实现

`src/verifier.py` 新增：

```python
@dataclass(frozen=True)
class TrustedCheckpoint:
    root: bytes
    version: int
```

- `root` 必须为 32 字节；`version` 必须为非负整数；显式拒绝 `bool`（`bool` 是 `int` 子类）与字符串等非法类型；非法 checkpoint 一律验证失败。
- `verify_state_proof(proof, trusted_old_checkpoint, trusted_new_checkpoint)` 取代旧的 `trusted_root`/`trusted_old_root` 字节接口，检查：
  - `proof.old_global_root == CP_old.root`
  - `proof.global_root == CP_new.root`
  - `proof.new_global_root == CP_new.root`
  - `proof.version_before == CP_old.version`
  - `proof.version_after == CP_new.version`
  - `proof.version == CP_new.version`
  - `CP_new.version == CP_old.version + 1`
- `verify_transition()` 使用相同可信检查点语义；旧的字节参数入口已移除，不存在绕过版本绑定的旧验证入口。
- 原有外层 SMT 路径、内层 SMT 路径、Agent 状态叶承诺、`grant_id`/`agent_tag` 绑定、tombstone 与 ACTIVE 区分均保留。

### 测试结果

| 用例 | 结果 |
| --- | --- |
| T17-A 真实检查点验证 | 通过 |
| T17-B 单独篡改 `proof.version` | 通过（拒绝） |
| T17-C 三个版本字段同时改为 100/101/101（保持递增） | 通过（拒绝） |
| T17-D 仅篡改新检查点版本 | 通过（拒绝） |
| T17-E 篡改旧/新检查点根 | 通过（拒绝） |
| T17-F 非法 checkpoint（31/33 字节根、负版本、bool、字符串；分别置于旧/新位置） | 通过（拒绝） |
| T17-G `verify_transition()` 三字段同步伪造 | 通过（拒绝） |

`tests/test_attacks.py` 与 `tests/test_registry.py` 中所有旧调用均迁移到检查点接口；T5、T6 原有攻击语义保留。测试辅助函数仅用本次实际转换构造检查点，**不代表 Registry 自生成的检查点天然可信**。

**信任前提与未实现项**：`TrustedCheckpoint` 必须由验证者从外部可信来源取得。本原型不实现检查点签名、透明日志、共识或来源认证；调用方任意构造的检查点不构成可信事实。版本绑定不等于检查点认证，也不证明 `S_{t+1} = Transition(S_t, e_t)`；状态转换证明仍未实现。

---

## 8.4 B1：同状态全量重建性能基准

### 实验定义与重建口径

- N = 初始化时单个 Agent 的 ACTIVE seed 授权数量；只用一个 Agent。
- 每个正式样本使用全新 Registry：N 条 ACTIVE seed 授权；预热使用独立 Registry；seed 初始化不计时。
- 每个样本依次：测 REGISTER → 从 REGISTER 后实际状态全量重建并断言根相等 → 测 REVOKE → 从 REVOKE 后实际状态全量重建并断言根相等。
- `rebuild_from_registry(registry)` 从实际存储读取每个 Agent 的内层叶（ACTIVE 与 REVOKED tombstone 均包含），校验 `SHA-256(key) == 叶路径`、`record.grant_id == key`、`record.agent_tag == 所属 Agent`；把全部记录写入**全新**内层 SMT；只用 ACTIVE 记录经独立 `recompute_aggregate()` 重算摘要（不读取 Registry 缓存摘要）；重建外层 Agent 状态叶并写入**全新**外层 SMT。不调用 Registry 增量状态转换函数，不复用当前树缓存节点或增量结果。
- 根一致性断言：REGISTER 后 `rebuilt_root == reg.get_global_root()` 且 ACTIVE 数 = N+1；REVOKE 后 `rebuilt_root == reg.get_global_root()` 且 ACTIVE 数 = N。任一失败即中止该规模并保留失败行，**不生成貌似成功的结果**。本轮无失败样本。

### 数据（每规模 30 次正式样本 + MEDIAN/P95）

| N | REGISTER 中位 / P95 (µs) | REVOKE 中位 / P95 (µs) | 重建(REGISTER后) 中位 / P95 (ms) | 重建(REVOKE后) 中位 / P95 (ms) | 增量哈希 (次) | 重建哈希 (次) | Oracle 中位 (µs) | 峰值内存 (MB) | 路径长度 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 16 | 1237.90 / 2581.93 | 1266.50 / 3539.26 | 12.404 / 17.063 | 11.879 / 19.506 | 514 / 514 | 4626 / 4626 | 56.15 | 1.09 | 256+256 |
| 64 | 1263.85 / 1737.90 | 1340.00 / 2111.74 | 47.266 / 55.636 | 47.959 / 58.514 | 514 / 514 | 16962 / 16962 | 187.70 | 3.41 | 256+256 |
| 256 | 1319.55 / 2202.22 | 1413.60 / 2517.47 | 199.248 / 214.185 | 198.879 / 214.913 | 514 / 514 | 66306 / 66306 | 684.85 | 12.93 | 256+256 |
| 1024 | 1640.60 / 3761.46 | 1517.40 / 2820.38 | 841.417 / 898.154 | 857.135 / 895.363 | 514 / 514 | 263682 / 263682 | 2725.70 | 50.53 | 256+256 |

同状态耗时比（全量重建中位数 / 单次增量中位数）：

| N | REGISTER 比 | REVOKE 比 |
| --- | --- | --- |
| 16 | 10.0× | 9.4× |
| 64 | 37.4× | 35.8× |
| 256 | 151.0× | 140.7× |
| 1024 | 512.9× | 564.9× |

### 根一致性检查结果

| N | REGISTER 后根（前 16 hex） | REVOKE 后根（前 16 hex） | 30 样本结果 |
| --- | --- | --- | --- |
| 16 | `82f8091ec433b565` | `ba5e3c51ef0f9bcd` | 两阶段均 OK |
| 64 | `204221c82dded768` | `f0faaf38a3fb91d8` | 两阶段均 OK |
| 256 | `1f2320ae2fa8118d` | `03cbbe313fac24d4` | 两阶段均 OK |
| 1024 | `6ff8222c0000c8aa` | `0fb577dd2ae2b94a` | 两阶段均 OK |

CSV 共 128 行（4 规模 × 30 原始样本 + 2 汇总行/规模），每行 `root_consistency_ok = OK`。完整根值、P95、哈希次数与全部样本见 `benchmarks/results_r2.csv`。

**口径说明**：比值是本 Python 原型中一次增量更新与完整状态重建的耗时对照，不是 ZKP 证明成本，也不是生产系统加速比；全量重建使用同一 SMT 原语逐叶插入但从空树开始，不复用当前树缓存。

---

## 8.5 T18：两个不同 issuer 的记录

- `grant_a = Grant(b"grant-from-issuer-a", b"A", b"ISSUER-A", EXPORT, 10)`
- `grant_b = Grant(b"grant-from-issuer-b", b"A", b"ISSUER-B", EXPORT, 20)`

| 步骤 | 结果 |
| --- | --- |
| 登记 A、B 两份授权 | 通过 |
| 聚合 | `Q = (2, 0, 30)`，与 Oracle 一致 |
| 两份授权的 SMT 成员证明 | 均通过；独立解码叶分别含 `ISSUER-A` / `ISSUER-B` |
| 两条叶路径属于同一 Agent 内层 root | 均通过 `verify_inner_root` |
| 撤销 issuer A 授权 | 通过 |
| 撤销后聚合 | `Q = (1, 0, 20)` |
| issuer B 授权 Gateway 执行 | 允许（version 3） |
| 已撤销 issuer A 授权 Gateway 执行 | 拒绝 `GRANT_NOT_FOUND` |
| 同 Agent 下不同 issuer 使用相同 `grant_id` | 拒绝 `DUPLICATE_GRANT_ID`（叶按 grant_id 唯一，不按 `(issuer, grant_id)` 唯一） |

**边界**：`issuer_id` 仍是标签；未实现签名或签名验证；不声称验证了多个独立发行者的真实身份，也不声称完成多发行者授权协议。

---

## 8.6 全量测试与最终裁决

### pytest 汇总

`python -m pytest tests/ -v` → **46 passed in 1.46s**，输出保存于 `results/test_output_r2.txt`。

- T1–T15 原有测试全部保留并通过，未被删除或弱化；T16-A~F、T17-A~G、T18 两组共 15 项新增测试全部通过。
- SMT、Registry、随机小样本测试继续通过。
- 本轮未修改 Registry 状态转换、随机操作生成或聚合规则，按任务包不重跑 10,000 次随机实验，也未覆盖 R1 随机证据。
- 无失败样本、无删除测试、无伪造数据。

### 裁决

**R2 验收通过**（四项任务全部满足验收标准）：重复 key / 重复路径标识被拒绝且 T16 限制如实保留；三个版本字段与可信检查点的 root/version 同时绑定且同步伪造被拒绝；REGISTER/REVOKE 两阶段同状态全量重建根完全相等、四档各 30 样本完整；两个 issuer 标签正确进入同一 Agent 聚合。

此裁决 **不自动批准进入 Halo2**。Halo2 是否立项仍需独立研究价值审查（相对已有机制的额外价值、隐藏授权集合下的完整集合证明与可验证增量状态转换）。当前 Halo2 裁决维持 **NO-GO（CONDITIONAL HOLD）**。

R2 结束后工程原型冻结：不得把 T16 的重复证明防护误认为完整集合证明，不得把 T17 的可信检查点绑定误认为检查点认证或共识。下一阶段关注的是密码学构造比较，而不是继续向本原型堆叠功能。
