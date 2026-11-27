# R5-A 冻结状态模型

本文件记录任务包 v1.0 冻结的系统模型。实现不得擅自修改此处定义。

## 1. 授权记录

```python
class Capability(Enum):
    EXPORT = 1
    DELETE = 2

@dataclass(frozen=True)
class Grant:
    grant_id: bytes
    agent_tag: bytes
    issuer_id: bytes
    capability: Capability
    budget: int
```

约束：

- `grant_id`、`agent_tag`、`issuer_id` 非空；
- `budget` 为 uint64，即 `0 ≤ budget ≤ 2^64 - 1`；
- `capability` 只能取 `EXPORT` 或 `DELETE`；
- 同一 Agent 内 `grant_id` 唯一；
- 记录登记后核心内容不可修改（`frozen=True`）。

本阶段 **不实现真实发行者签名**。`issuer_id` 只是字符串标签，不代表任何经过密码学验证的身份。

## 2. 聚合摘要

```python
@dataclass(frozen=True)
class Aggregate:
    export_count: int
    delete_count: int
    budget_sum: int
```

记 `Q = (n_E, n_D, B)`。初始状态 `Q0 = (0, 0, 0)`。

策略（对每个 Agent 独立成立）：

```
Φ(Q) = (n_E = 0 ∨ n_D = 0) ∧ (B ≤ 100)
```

所有数值使用普通整数语义，并限制在 uint64 范围内。超过 uint64 或违反 `Φ` 的更新必须被拒绝。

注：`Φ` 是一个为实验冻结的人造不变量，用于产生可判定拒绝；它不是现实中的授权语义。

## 3. 双层 SMT

```
Global SMT (256 层)
  |
  +-- agent_tag_A -> H(inner_root_A, aggregate_A)
  +-- agent_tag_B -> H(inner_root_B, aggregate_B)
  +-- agent_tag_C -> H(inner_root_C, aggregate_C)

Agent Inner SMT (256 层, 按 Agent 隔离)
  |
  +-- grant_id_1 -> Grant Record
  +-- grant_id_2 -> Grant Record
```

- 哈希函数：SHA-256。
- 固定深度：256 层。
- 空叶子使用域分离哈希。
- 内层树按 Agent 隔离；外层树承诺 Agent 内层根与聚合摘要。
- 支持 membership 与 non-membership proof。
- 支持独立验证 SMT 路径。
- **必须**采用缓存节点的增量路径更新：修改一片叶子最多更新 256 个父节点；禁止每次从全部叶子重建整棵树。

## 4. 状态转换

REGISTER（增量）：

```
EXPORT: Q' = (n_E + 1, n_D,     B + b)
DELETE: Q' = (n_E,     n_D + 1, B + b)
```

执行顺序：验证输入 → 检查 `grant_id` 不存在 → 计算新摘要 → 检查数值范围 → 检查 `Φ` → 计算新内层根 → 计算新外层根 → 原子提交 → `version += 1`。

REVOKE（增量）：

```
EXPORT: Q' = (n_E - 1, n_D,     B - b)
DELETE: Q' = (n_E,     n_D - 1, B - b)
```

关键约束：

- 必须从 Registry 读取原授权；
- 不接受调用方提供的 `capability` 与 `budget`；
- 只允许撤销 ACTIVE 授权；
- 撤销失败不能修改任何状态；
- 不允许计数器下溢。

### R5-A-R1 修正：撤销 tombstone

撤销 **不删除** 内层叶，而是写入带 `R5A-TOMBSTONE-v1` 前缀的不可复用记录（保留 grant_id、
agent_tag、原 capability 与 budget）。后果：

- `grant_id` 在同一 Agent 内一旦登记（无论 ACTIVE 还是 REVOKED）永不复用；`register` 遇到
  tombstone 返回 `GRANT_ID_REUSED`，遇到 ACTIVE 重复返回 `DUPLICATE_GRANT_ID`。
- `Aggregate` 只统计 ACTIVE 叶，tombstone 不影响 `n_E / n_D / B`。
- `revoke` / `gateway_authorize` 遇到 tombstone 一律按 `GRANT_NOT_FOUND` 拒绝。
- tombstone 仍被内层根承诺，独立验证器能区分 tombstone 与 ACTIVE 记录。

## 5. CAS 与版本

若 `expected_version != current_version`，必须拒绝更新。

初始 `version = 0`；每次成功提交 `version += 1`。

本阶段 **只验证单进程 CAS**，不得声称已经实现分布式共识、多节点线性一致性或 exactly-once 语义。

## 6. Gateway

`gateway_authorize(agent_tag, grant_id, expected_version)` 只读取状态并检查：授权存在且 ACTIVE、version 匹配、策略仍成立。它不执行任何外部动作，也不验证签名。
