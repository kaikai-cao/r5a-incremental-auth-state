"""SMT 增量路径、成员/非成员证明与篡改拒绝测试。"""

from __future__ import annotations

import random
from dataclasses import replace

from src.smt import DEPTH, SMT, get_hash_count, reset_hash_count
from src.verifier import verify_nonmembership, verify_path


def test_incremental_root_is_order_independent():
    keys = [f"key-{i:03d}".encode() for i in range(120)]
    values = {k: b"value-" + k for k in keys}

    incremental = SMT()
    for key in keys:
        incremental.set(key, values[key])

    rebuilt = SMT()
    for key in reversed(keys):
        rebuilt.set(key, values[key])

    shuffled = keys[:]
    random.Random(7).shuffle(shuffled)
    shuffled_tree = SMT()
    for key in shuffled:
        shuffled_tree.set(key, values[key])

    assert incremental.root == rebuilt.root == shuffled_tree.root


def test_membership_and_nonmembership_paths():
    tree = SMT()
    keys = [f"k{i}".encode() for i in range(64)]
    for i, key in enumerate(keys):
        tree.set(key, f"v{i}".encode())

    for key in keys:
        proof = tree.prove(key)
        assert verify_path(proof.key, proof.value, proof.siblings, proof.root)

    for i in range(64):
        absent = f"absent-{i}".encode()
        proof = tree.prove(absent)
        assert proof.value is None
        assert verify_nonmembership(proof)


def test_empty_tree_nonmembership():
    tree = SMT()
    proof = tree.prove(b"never-inserted")
    assert verify_nonmembership(proof)


def test_tampered_siblings_value_and_root_are_rejected():
    tree = SMT()
    tree.set(b"alpha", b"one")
    tree.set(b"beta", b"two")
    proof = tree.prove(b"alpha")
    assert verify_path(proof.key, proof.value, proof.siblings, proof.root)

    bad_siblings = list(proof.siblings)
    bad_siblings[0] = bytes([bad_siblings[0][0] ^ 0x01]) + bad_siblings[0][1:]
    assert not verify_path(proof.key, proof.value, bad_siblings, proof.root)

    assert not verify_path(proof.key, b"tampered-value", proof.siblings, proof.root)
    assert not verify_path(proof.key, proof.value, proof.siblings, b"\x00" * 32)
    assert not verify_path(
        replace(proof, key=b"different-key").key,
        proof.value,
        proof.siblings,
        proof.root,
    )
    assert not verify_path(proof.key, proof.value, proof.siblings[:-1], proof.root)


def test_one_update_changes_at_most_256_parent_nodes():
    tree = SMT()
    for i in range(100):
        tree.set(f"seed-{i}".encode(), f"v-{i}".encode())

    preview = tree.preview_set(b"new-leaf", b"payload")
    assert len(preview.changes) == DEPTH

    reset_hash_count()
    tree.apply(preview)
    # apply 阶段只写缓存，不做哈希；预演阶段最多 256 个内部节点 + 1 个叶哈希 + 旁路叶哈希。
    assert get_hash_count() == 0

    reset_hash_count()
    tree.set(b"another-leaf", b"payload-2")
    assert get_hash_count() <= DEPTH + 4


def test_delete_returns_to_empty_root():
    tree = SMT()
    tree.set(b"x", b"y")
    tree.set(b"x", None)
    assert tree.root == SMT().root
    assert verify_nonmembership(tree.prove(b"x"))
