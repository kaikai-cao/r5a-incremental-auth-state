"""R5-A 256 层稀疏 Merkle 树（SHA-256，增量缓存路径更新）。

关键约束：
  - 固定 256 层；空子树使用预计算默认哈希，域分离空叶子；
  - 每次叶子修改只重算该路径上的 256 个父节点，绝不遍历全部叶子；
  - 提供成员 / 非成员证明所需的兄弟路径；
  - 路径验证逻辑在 verifier.py 中独立实现（本模块不提供验证函数）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_DOMAIN = b"R5A-SMT-LEAF-v1"
NODE_DOMAIN = b"R5A-SMT-NODE-v1"
EMPTY_DOMAIN = b"R5A-SMT-EMPTY-v1"
DEPTH = 256

_HASH_COUNT = 0


def sha(data: bytes) -> bytes:
    global _HASH_COUNT
    _HASH_COUNT += 1
    return hashlib.sha256(data).digest()


def reset_hash_count() -> None:
    global _HASH_COUNT
    _HASH_COUNT = 0


def get_hash_count() -> int:
    return _HASH_COUNT


def leaf_hash(value: bytes) -> bytes:
    return sha(LEAF_DOMAIN + value)


def internal_node(left: bytes, right: bytes) -> bytes:
    return sha(NODE_DOMAIN + left + right)


EMPTY_LEAF = leaf_hash(EMPTY_DOMAIN + b"empty")

# EMPTY_HASHES[d] = 深度 d 处全空子树的根哈希；EMPTY_HASHES[256] = 空叶子。
EMPTY_HASHES: list[bytes] = [b""] * (DEPTH + 1)
EMPTY_HASHES[DEPTH] = EMPTY_LEAF
for _d in range(DEPTH - 1, -1, -1):
    EMPTY_HASHES[_d] = internal_node(EMPTY_HASHES[_d + 1], EMPTY_HASHES[_d + 1])
reset_hash_count()  # 预计算不计入实验哈希计数


@dataclass(frozen=True)
class SMTProof:
    key: bytes
    value: bytes | None
    siblings: tuple[bytes, ...]
    root: bytes


@dataclass(frozen=True)
class Preview:
    """一次叶子修改的预演结果；apply 只写入缓存，不重新哈希。"""

    new_root: bytes
    changes: tuple[tuple[tuple[int, int], bytes | None], ...]
    path: int
    value: bytes | None
    key: bytes


class SMT:
    """稀疏 Merkle 树：只保存非空叶子与偏离默认值的内部节点。"""

    def __init__(self) -> None:
        self.leaves: dict[int, bytes] = {}
        self.keys: dict[int, bytes] = {}
        self.nodes: dict[tuple[int, int], bytes] = {}
        self._root = EMPTY_HASHES[0]

    @property
    def root(self) -> bytes:
        return self._root

    @property
    def item_count(self) -> int:
        return len(self.leaves)

    @staticmethod
    def _path_int(key: bytes) -> int:
        if not isinstance(key, bytes) or len(key) == 0:
            raise ValueError("SMT key must be non-empty bytes")
        # 键路径哈希不计入「更新路径哈希次数」指标，它只是索引。
        return int.from_bytes(hashlib.sha256(key).digest(), "big")

    def _get_node_hash(self, depth: int, index: int) -> bytes:
        if depth == DEPTH:
            value = self.leaves.get(index)
            return leaf_hash(value) if value is not None else EMPTY_LEAF
        return self.nodes.get((depth, index), EMPTY_HASHES[depth])

    def preview_set(self, key: bytes, value: bytes | None) -> Preview:
        """预演一次设置/删除，返回新根与缓存变更；不修改树状态。"""
        path = self._path_int(key)
        current = leaf_hash(value) if value is not None else EMPTY_LEAF
        changes: list[tuple[tuple[int, int], bytes | None]] = []
        for depth in range(DEPTH - 1, -1, -1):
            index = path >> (DEPTH - depth)
            goes_right = (path >> (DEPTH - 1 - depth)) & 1
            if goes_right:
                sibling = self._get_node_hash(depth + 1, index << 1)
                node = internal_node(sibling, current)
            else:
                sibling = self._get_node_hash(depth + 1, (index << 1) | 1)
                node = internal_node(current, sibling)
            if node == EMPTY_HASHES[depth]:
                changes.append(((depth, index), None))
            else:
                changes.append(((depth, index), node))
            current = node
        return Preview(current, tuple(changes), path, value, key)

    def apply(self, preview: Preview) -> None:
        """提交 preview 的变更；无哈希计算，失败路径不会调用。"""
        if preview.value is None:
            self.leaves.pop(preview.path, None)
            self.keys.pop(preview.path, None)
        else:
            self.leaves[preview.path] = preview.value
            self.keys[preview.path] = preview.key
        for (depth, index), node_hash in preview.changes:
            if node_hash is None:
                self.nodes.pop((depth, index), None)
            else:
                self.nodes[(depth, index)] = node_hash
        self._root = preview.new_root

    def set(self, key: bytes, value: bytes | None) -> None:
        self.apply(self.preview_set(key, value))

    def get(self, key: bytes) -> bytes | None:
        return self.leaves.get(self._path_int(key))

    def contains(self, key: bytes) -> bool:
        return self.get(key) is not None

    def prove_by_path(self, path: int) -> SMTProof:
        """按已知叶路径生成证明（用于枚举全部叶，避免重新哈希键）。"""
        siblings: list[bytes] = []
        for depth in range(DEPTH):
            index = path >> (DEPTH - depth)
            goes_right = (path >> (DEPTH - 1 - depth)) & 1
            sibling_index = (index << 1) if goes_right else ((index << 1) | 1)
            siblings.append(self._get_node_hash(depth + 1, sibling_index))
        return SMTProof(
            key=self.keys.get(path, b""),
            value=self.leaves.get(path),
            siblings=tuple(siblings),
            root=self.root,
        )

    def prove(self, key: bytes) -> SMTProof:
        """生成 256 个兄弟哈希的路径证明；value=None 表示非成员证明。"""
        path = self._path_int(key)
        siblings: list[bytes] = []
        for depth in range(DEPTH):
            index = path >> (DEPTH - depth)
            goes_right = (path >> (DEPTH - 1 - depth)) & 1
            sibling_index = (index << 1) if goes_right else ((index << 1) | 1)
            siblings.append(self._get_node_hash(depth + 1, sibling_index))
        return SMTProof(
            key=key,
            value=self.leaves.get(path),
            siblings=tuple(siblings),
            root=self.root,
        )
