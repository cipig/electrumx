#!/usr/bin/env python3
# Copyright (c) 2021 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

#
# zip244.py
#
# Functionality to create txids, auth digests, and signature digests.
#
# This file is modified from zcash/zcash-test-vectors.
#

import struct

from hashlib import blake2b

from .mininode import ser_string, ser_uint256
from .script import (
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    getHashOutputs,
    getHashPrevouts,
    getHashSequence,
)


# Transparent

def transparent_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    if len(tx.vin) + len(tx.vout) > 0:
        digest.update(getHashPrevouts(tx, b'ZTxIdPrevoutHash'))
        digest.update(getHashSequence(tx, b'ZTxIdSequencHash'))
        digest.update(getHashOutputs(tx, b'ZTxIdOutputsHash'))

    return digest.digest()

def transparent_scripts_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxAuthTransHash')
    for txin in tx.vin:
        digest.update(ser_string(txin.scriptSig))
    return digest.digest()

# Sapling

def sapling_digest(saplingBundle, v6=False):
    digest = blake2b(digest_size=32, person=b'ZTxIdSaplingHash')

    if len(saplingBundle.spends) + len(saplingBundle.outputs) > 0:
        digest.update(sapling_spends_digest(saplingBundle, v6))
        digest.update(sapling_outputs_digest(saplingBundle))
        digest.update(struct.pack('<q', saplingBundle.valueBalance))

    return digest.digest()

def sapling_auth_digest(saplingBundle, v6=False):
    person = b'ZTxAuthSapliH_v6' if v6 else b'ZTxAuthSapliHash'
    digest = blake2b(digest_size=32, person=person)

    if len(saplingBundle.spends) + len(saplingBundle.outputs) > 0:
        for desc in saplingBundle.spends:
            digest.update(desc.zkproof.serialize())
        for desc in saplingBundle.spends:
            digest.update(desc.spendAuthSig.serialize())
        for desc in saplingBundle.outputs:
            digest.update(desc.zkproof.serialize())
        digest.update(saplingBundle.bindingSig.serialize())
        if v6 and len(saplingBundle.spends) > 0:
            digest.update(ser_uint256(saplingBundle.anchor))

    return digest.digest()

# - Spends

def sapling_spends_digest(saplingBundle, v6=False):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendsHash')

    if len(saplingBundle.spends) > 0:
        digest.update(sapling_spends_compact_digest(saplingBundle))
        digest.update(sapling_spends_noncompact_digest(saplingBundle, v6))

    return digest.digest()

def sapling_spends_compact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSSpendCHash')
    for desc in saplingBundle.spends:
        digest.update(ser_uint256(desc.nullifier))
    return digest.digest()

def sapling_spends_noncompact_digest(saplingBundle, v6=False):
    person = b'ZTxIdSSpendNH_v6' if v6 else b'ZTxIdSSpendNHash'
    digest = blake2b(digest_size=32, person=person)
    for desc in saplingBundle.spends:
        digest.update(ser_uint256(desc.cv))
        if not v6:
            digest.update(ser_uint256(saplingBundle.anchor))
        digest.update(ser_uint256(desc.rk))
    return digest.digest()

# - Outputs

def sapling_outputs_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutputHash')

    if len(saplingBundle.outputs) > 0:
        digest.update(sapling_outputs_compact_digest(saplingBundle))
        digest.update(sapling_outputs_memos_digest(saplingBundle))
        digest.update(sapling_outputs_noncompact_digest(saplingBundle))

    return digest.digest()

def sapling_outputs_compact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutC__Hash')
    for desc in saplingBundle.outputs:
        digest.update(ser_uint256(desc.cmu))
        digest.update(ser_uint256(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()

def sapling_outputs_memos_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutM__Hash')
    for desc in saplingBundle.outputs:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()

def sapling_outputs_noncompact_digest(saplingBundle):
    digest = blake2b(digest_size=32, person=b'ZTxIdSOutN__Hash')
    for desc in saplingBundle.outputs:
        digest.update(ser_uint256(desc.cv))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()


class _OrchardPers:
    def __init__(self, bundle, compact, memos, noncompact, auth,
                 anchor_in_txid, anchor_in_auth):
        self.bundle = bundle
        self.compact = compact
        self.memos = memos
        self.noncompact = noncompact
        self.auth = auth
        self.anchor_in_txid = anchor_in_txid
        self.anchor_in_auth = anchor_in_auth


ORCHARD_V5 = _OrchardPers(
    b'ZTxIdOrchardHash', b'ZTxIdOrcActCHash', b'ZTxIdOrcActMHash',
    b'ZTxIdOrcActNHash', b'ZTxAuthOrchaHash', True, False)
ORCHARD_V6 = _OrchardPers(
    b'ZTxIdOrchardH_v6', b'ZTxIdOrcActCHash', b'ZTxIdOrcActMHash',
    b'ZTxIdOrcActNHash', b'ZTxAuthOrchaH_v6', False, True)
IRONWOOD_V6 = _OrchardPers(
    b'ZTxIdIronwd_H_v6', b'ZTxIdIrnActCH_v6', b'ZTxIdIrnActMH_v6',
    b'ZTxIdIrnActNH_v6', b'ZTxAuthIrnwdH_v6', False, True)


def _orchard_style_digest(bundle, pers):
    digest = blake2b(digest_size=32, person=pers.bundle)

    if len(bundle.actions) > 0:
        digest.update(_orchard_actions_compact_digest(bundle, pers))
        digest.update(_orchard_actions_memos_digest(bundle, pers))
        digest.update(_orchard_actions_noncompact_digest(bundle, pers))
        digest.update(struct.pack('B', bundle.flags()))
        digest.update(struct.pack('<q', bundle.valueBalance))
        if pers.anchor_in_txid:
            digest.update(ser_uint256(bundle.anchor))

    return digest.digest()


def _orchard_style_auth_digest(bundle, pers):
    digest = blake2b(digest_size=32, person=pers.auth)

    if len(bundle.actions) > 0:
        digest.update(bytes(bundle.proofs))
        for desc in bundle.actions:
            digest.update(desc.spendAuthSig.serialize())
        digest.update(bundle.bindingSig.serialize())
        if pers.anchor_in_auth:
            digest.update(ser_uint256(bundle.anchor))

    return digest.digest()


def orchard_digest(orchardBundle, v6=False):
    return _orchard_style_digest(orchardBundle, ORCHARD_V6 if v6 else ORCHARD_V5)


def orchard_auth_digest(orchardBundle, v6=False):
    return _orchard_style_auth_digest(orchardBundle, ORCHARD_V6 if v6 else ORCHARD_V5)


def ironwood_digest(ironwoodBundle):
    return _orchard_style_digest(ironwoodBundle, IRONWOOD_V6)


def ironwood_auth_digest(ironwoodBundle):
    return _orchard_style_auth_digest(ironwoodBundle, IRONWOOD_V6)


def _orchard_actions_compact_digest(bundle, pers):
    digest = blake2b(digest_size=32, person=pers.compact)
    for desc in bundle.actions:
        digest.update(ser_uint256(desc.nullifier))
        digest.update(ser_uint256(desc.cmx))
        digest.update(ser_uint256(desc.ephemeralKey))
        digest.update(desc.encCiphertext[:52])
    return digest.digest()


def _orchard_actions_memos_digest(bundle, pers):
    digest = blake2b(digest_size=32, person=pers.memos)
    for desc in bundle.actions:
        digest.update(desc.encCiphertext[52:564])
    return digest.digest()


def _orchard_actions_noncompact_digest(bundle, pers):
    digest = blake2b(digest_size=32, person=pers.noncompact)
    for desc in bundle.actions:
        digest.update(ser_uint256(desc.cv))
        digest.update(ser_uint256(desc.rk))
        digest.update(desc.encCiphertext[564:])
        digest.update(desc.outCiphertext)
    return digest.digest()


def header_digest(tx):
    digest = blake2b(digest_size=32, person=b'ZTxIdHeadersHash')

    digest.update(struct.pack('<I', (int(tx.fOverwintered) << 31) | tx.nVersion))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(struct.pack('<I', tx.nConsensusBranchId))
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))

    return digest.digest()


def is_v6(tx):
    return (
        tx.fOverwintered
        and tx.nVersion == 6
        and tx.nVersionGroupId == 0xD884B698
    )


def txid_digest(tx):
    v6 = is_v6(tx)
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_digest(tx))
    digest.update(sapling_digest(tx.saplingBundle, v6))
    digest.update(orchard_digest(tx.orchardBundle, v6))
    if v6:
        digest.update(ironwood_digest(tx.ironwoodBundle))

    return digest.digest()


def auth_digest(tx):
    v6 = is_v6(tx)
    digest = blake2b(
        digest_size=32,
        person=b'ZTxAuthHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(transparent_scripts_digest(tx))
    digest.update(sapling_auth_digest(tx.saplingBundle, v6))
    digest.update(orchard_auth_digest(tx.orchardBundle, v6))
    if v6:
        digest.update(ironwood_auth_digest(tx.ironwoodBundle))

    return digest.digest()


def signature_digest(tx, nHashType, txin):
    v6 = is_v6(tx)
    digest = blake2b(
        digest_size=32,
        person=b'ZcashTxHash_' + struct.pack('<I', tx.nConsensusBranchId),
    )

    digest.update(header_digest(tx))
    digest.update(transparent_sig_digest(tx, nHashType, txin))
    digest.update(sapling_digest(tx.saplingBundle, v6))
    digest.update(orchard_digest(tx.orchardBundle, v6))
    if v6:
        digest.update(ironwood_digest(tx.ironwoodBundle))

    return digest.digest()


def transparent_sig_digest(tx, nHashType, txin):
    if txin is None:
        return transparent_digest(tx)

    digest = blake2b(digest_size=32, person=b'ZTxIdTranspaHash')

    digest.update(prevouts_sig_digest(tx, nHashType))
    digest.update(sequence_sig_digest(tx, nHashType))
    digest.update(outputs_sig_digest(tx, nHashType, txin))
    digest.update(txin_sig_digest(tx, txin))

    return digest.digest()


def prevouts_sig_digest(tx, nHashType):
    if not (nHashType & SIGHASH_ANYONECANPAY):
        return getHashPrevouts(tx, b'ZTxIdPrevoutHash')
    return blake2b(digest_size=32, person=b'ZTxIdPrevoutHash').digest()


def sequence_sig_digest(tx, nHashType):
    if (
        (not (nHashType & SIGHASH_ANYONECANPAY))
        and (nHashType & 0x1f) != SIGHASH_SINGLE
        and (nHashType & 0x1f) != SIGHASH_NONE
    ):
        return getHashSequence(tx, b'ZTxIdSequencHash')
    return blake2b(digest_size=32, person=b'ZTxIdSequencHash').digest()


def outputs_sig_digest(tx, nHashType, txin):
    if (nHashType & 0x1f) != SIGHASH_SINGLE and (nHashType & 0x1f) != SIGHASH_NONE:
        return getHashOutputs(tx, b'ZTxIdOutputsHash')

    if (nHashType & 0x1f) == SIGHASH_SINGLE and 0 <= txin.nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'ZTxIdOutputsHash')
        digest.update(bytes(tx.vout[txin.nIn]))
        return digest.digest()

    return blake2b(digest_size=32, person=b'ZTxIdOutputsHash').digest()


def txin_sig_digest(tx, txin):
    digest = blake2b(digest_size=32, person=b'Zcash___TxInHash')
    digest.update(bytes(tx.vin[txin.nIn].prevout))
    digest.update(ser_string(txin.scriptCode))
    digest.update(struct.pack('<Q', txin.amount))
    digest.update(struct.pack('<I', tx.vin[txin.nIn].nSequence))
    return digest.digest()
