import copy
import struct
from hashlib import blake2b
from io import BytesIO

from electrumx.lib.hash import hash_to_hex_str
from electrumx.lib.tx import DeserializerZcash
from electrumx.lib.zcash import zip244
from electrumx.lib.zcash.mininode import (
    CTransaction,
    Groth16Proof,
    IronwoodBundle,
    OrchardAction,
    OrchardBundle,
    OutputDescriptionV5,
    RedJubjubSignature,
    RedPallasSignature,
    SaplingBundle,
    SpendDescriptionV5,
)


NU63_BRANCH_ID = 0x37A5165B
ZIP229_VERSION_GROUP_ID = 0xD884B698
ZIP225_VERSION_GROUP_ID = 0x26A7270A


def _u256(byte):
    return int.from_bytes(bytes([byte]) * 32, "little")


def _proof(byte):
    proof = Groth16Proof()
    proof.data = bytes([byte]) * 192
    return proof


def _jubjub_sig(byte):
    sig = RedJubjubSignature()
    sig.data = bytes([byte]) * 64
    return sig


def _pallas_sig(byte):
    sig = RedPallasSignature()
    sig.data = bytes([byte]) * 64
    return sig


def _orchard_action(byte):
    action = OrchardAction()
    action.cv = _u256(byte)
    action.nullifier = _u256(byte + 1)
    action.rk = _u256(byte + 2)
    action.cmx = _u256(byte + 3)
    action.ephemeralKey = _u256(byte + 4)
    action.encCiphertext = bytes([byte + 5]) * 580
    action.outCiphertext = bytes([byte + 6]) * 80
    action.spendAuthSig = _pallas_sig(byte + 7)
    return action


def _orchard_bundle(byte, *, cls=OrchardBundle):
    bundle = cls()
    bundle.actions = [_orchard_action(byte)]
    bundle.enableSpends = True
    bundle.enableOutputs = True
    bundle.enableCrossAddress = False
    bundle.valueBalance = 123456789
    bundle.anchor = _u256(byte + 8)
    bundle.proofs = bytes([byte + 9]) * (2720 + 2272 * len(bundle.actions))
    bundle.bindingSig = _pallas_sig(byte + 10)
    return bundle


def _sapling_bundle(byte):
    spend = SpendDescriptionV5()
    spend.cv = _u256(byte)
    spend.nullifier = _u256(byte + 1)
    spend.rk = _u256(byte + 2)
    spend.zkproof = _proof(byte + 3)
    spend.spendAuthSig = _jubjub_sig(byte + 4)

    output = OutputDescriptionV5()
    output.cv = _u256(byte + 5)
    output.cmu = _u256(byte + 6)
    output.ephemeralKey = _u256(byte + 7)
    output.encCiphertext = bytes([byte + 8]) * 580
    output.outCiphertext = bytes([byte + 9]) * 80
    output.zkproof = _proof(byte + 10)

    bundle = SaplingBundle()
    bundle.spends = [spend]
    bundle.outputs = [output]
    bundle.valueBalance = -1234567
    bundle.anchor = _u256(byte + 11)
    bundle.bindingSig = _jubjub_sig(byte + 12)
    return bundle


def _v6_tx():
    tx = CTransaction()
    tx.fOverwintered = True
    tx.nVersion = 6
    tx.nVersionGroupId = ZIP229_VERSION_GROUP_ID
    tx.nConsensusBranchId = NU63_BRANCH_ID
    tx.nLockTime = 0
    tx.nExpiryHeight = 0
    tx.saplingBundle = SaplingBundle()
    tx.orchardBundle = OrchardBundle()
    tx.ironwoodBundle = IronwoodBundle()
    return tx


def _v5_tx():
    tx = _v6_tx()
    tx.nVersion = 5
    tx.nVersionGroupId = ZIP225_VERSION_GROUP_ID
    return tx


def _empty_hash(personal):
    return blake2b(digest_size=32, person=personal).digest()


def test_v6_empty_auth_digest_uses_v6_personalizations():
    tx = _v6_tx()
    expected = blake2b(
        digest_size=32,
        person=b"ZTxAuthHash_" + struct.pack("<I", NU63_BRANCH_ID),
    )
    expected.update(_empty_hash(b"ZTxAuthTransHash"))
    expected.update(_empty_hash(b"ZTxAuthSapliH_v6"))
    expected.update(_empty_hash(b"ZTxAuthOrchaH_v6"))
    expected.update(_empty_hash(b"ZTxAuthIrnwdH_v6"))
    assert zip244.auth_digest(tx) == expected.digest()


def test_v6_empty_txid_uses_v6_personalizations():
    tx = _v6_tx()
    expected = blake2b(
        digest_size=32,
        person=b"ZcashTxHash_" + struct.pack("<I", NU63_BRANCH_ID),
    )
    expected.update(zip244.header_digest(tx))
    expected.update(_empty_hash(b"ZTxIdTranspaHash"))
    expected.update(_empty_hash(b"ZTxIdSaplingHash"))
    expected.update(_empty_hash(b"ZTxIdOrchardH_v6"))
    expected.update(_empty_hash(b"ZTxIdIronwd_H_v6"))
    assert zip244.txid_digest(tx) == expected.digest()


def test_v6_ironwood_anchor_changes_auth_digest_not_txid():
    tx_a = _v6_tx()
    tx_b = _v6_tx()
    tx_a.ironwoodBundle = _orchard_bundle(11, cls=IronwoodBundle)
    tx_b.ironwoodBundle = copy.deepcopy(tx_a.ironwoodBundle)
    tx_b.ironwoodBundle.anchor = _u256(42)

    assert tx_a.serialize() != tx_b.serialize()
    assert zip244.txid_digest(tx_a) == zip244.txid_digest(tx_b)
    assert zip244.auth_digest(tx_a) != zip244.auth_digest(tx_b)


def test_v6_orchard_anchor_changes_auth_digest_not_txid():
    tx_a = _v6_tx()
    tx_b = _v6_tx()
    tx_a.orchardBundle = _orchard_bundle(16)
    tx_b.orchardBundle = copy.deepcopy(tx_a.orchardBundle)
    tx_b.orchardBundle.anchor = _u256(46)

    assert tx_a.serialize() != tx_b.serialize()
    assert zip244.txid_digest(tx_a) == zip244.txid_digest(tx_b)
    assert zip244.auth_digest(tx_a) != zip244.auth_digest(tx_b)


def test_v6_sapling_anchor_changes_auth_digest_not_txid():
    tx_a = _v6_tx()
    tx_b = _v6_tx()
    tx_a.saplingBundle = _sapling_bundle(21)
    tx_b.saplingBundle = copy.deepcopy(tx_a.saplingBundle)
    tx_b.saplingBundle.anchor = _u256(84)

    assert tx_a.serialize() != tx_b.serialize()
    assert zip244.txid_digest(tx_a) == zip244.txid_digest(tx_b)
    assert zip244.auth_digest(tx_a) != zip244.auth_digest(tx_b)


def test_v5_orchard_anchor_still_changes_txid_not_auth():
    tx_a = _v5_tx()
    tx_b = _v5_tx()
    tx_a.orchardBundle = _orchard_bundle(31)
    tx_b.orchardBundle = copy.deepcopy(tx_a.orchardBundle)
    tx_b.orchardBundle.anchor = _u256(93)

    assert zip244.txid_digest(tx_a) != zip244.txid_digest(tx_b)
    assert zip244.auth_digest(tx_a) == zip244.auth_digest(tx_b)


def test_v6_ironwood_empty_and_nonempty_component_digests():
    empty_bundle = IronwoodBundle()
    nonempty_bundle = _orchard_bundle(71, cls=IronwoodBundle)

    assert zip244.ironwood_digest(empty_bundle) == _empty_hash(b"ZTxIdIronwd_H_v6")
    assert zip244.ironwood_auth_digest(empty_bundle) == _empty_hash(b"ZTxAuthIrnwdH_v6")
    assert zip244.ironwood_digest(nonempty_bundle) != zip244.ironwood_digest(empty_bundle)
    assert zip244.ironwood_auth_digest(nonempty_bundle) != zip244.ironwood_auth_digest(empty_bundle)


def test_v6_roundtrip_deserialize_serialize_and_txid_with_ironwood():
    tx = _v6_tx()
    tx.saplingBundle = _sapling_bundle(41)
    tx.orchardBundle = _orchard_bundle(51)
    tx.ironwoodBundle = _orchard_bundle(61, cls=IronwoodBundle)

    raw_tx = tx.serialize()

    parsed = CTransaction()
    parsed.deserialize(BytesIO(raw_tx))
    assert parsed.serialize() == raw_tx

    deser_tx = DeserializerZcash(raw_tx).read_tx()
    assert deser_tx.version == 6
    assert hash_to_hex_str(deser_tx.txid_rev) == hash_to_hex_str(zip244.txid_digest(parsed))
