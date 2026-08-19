import pytest

from electrumx.lib.coins import Bitcoin, CoinError, Ravencoin, RavencoinTestnet
from electrumx.server.ravencoin_backend import (
    BackendIdentity,
    INCIDENT_CHECKPOINT_HASH,
    KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT,
    RavencoinDaemon,
    RavencoinElectrumX,
    configure_ravencoin_coin,
    evaluate_backend,
    parse_core_version,
)
from electrumx.server.session import ElectrumX


SAFE_NETWORK_INFO = {
    'version': 4_080_000,
    'protocolversion': 70028,
    'subversion': '/Ravencoin:4.8.0/',
}
SAFE_BLOCKCHAIN_INFO = {
    'chain': 'main',
    'blocks': 4_500_000,
    'headers': 4_500_000,
    'initialblockdownload': False,
}


class TestRavencoin(Ravencoin):
    pass


class TestRavencoinTestnet(RavencoinTestnet):
    pass


def _header_with_height(coin, height):
    header = bytearray(coin.KAWPOW_HEADER_SIZE)
    header[76:80] = int(height).to_bytes(4, 'little')
    return bytes(header)


def test_ravencoin_version_encoding_is_not_bitcoin_encoding():
    assert parse_core_version(4_080_000) == (4, 8, 0, 0)


def test_backend_payload_matches_electrum_ravencoin_contract():
    status = evaluate_backend(
        SAFE_NETWORK_INFO,
        SAFE_BLOCKCHAIN_INFO,
        'mainnet',
        checkpoint_hash=INCIDENT_CHECKPOINT_HASH,
        observed_at=1_777_000_000,
    )
    identity = BackendIdentity.from_config(
        repository='2miners/Ravencoin',
        tag='v4.8.0',
        commit='b60f50e04f1fba425b28804e61be2694faaf3469',
        artifact_sha256=(
            '966cf8978af1f2e3f36e9733d011eb92'
            'f4116750af6f8e77c5a5ced525577c4c'
        ),
        evidence='BUILD_IDENTITY_VERIFIED',
    )
    payload = status.public_dict(
        'ElectrumX 2.0.0',
        identity=identity,
        kawpow_height_validation=True,
    )

    assert payload['backend']['name'] == 'Ravencoin Core'
    assert payload['backend']['version'] == '4.8.0'
    assert payload['backend']['versionNumber'] == 4_080_000
    assert payload['backend']['subversion'] == '/Ravencoin:4.8.0/'
    assert payload['backend']['network'] == 'main'
    assert payload['backend']['identity']['sourceRepository'] == '2miners/Ravencoin'
    assert payload['compatibility']['minimumSafeCore'] == '4.8.0'
    assert payload['compatibility']['coreSafe'] is True
    assert payload['compatibility']['networkMatches'] is True
    assert payload['compatibility']['backendSynchronized'] is True
    assert payload['compatibility']['kawpowHeightValidation'] is True
    assert payload['compatibility']['checkpoint4487775'] is True


def test_pre_480_backend_is_reported_unsafe():
    network_info = dict(
        SAFE_NETWORK_INFO,
        version=4_070_000,
        subversion='/Ravencoin:4.7.0/',
    )
    status = evaluate_backend(
        network_info,
        SAFE_BLOCKCHAIN_INFO,
        'mainnet',
        checkpoint_hash=INCIDENT_CHECKPOINT_HASH,
        observed_at=1_777_000_000,
    )
    assert status.version_safe is False
    assert status.core_safe is False


def test_wrong_checkpoint_is_reported_unsafe():
    status = evaluate_backend(
        SAFE_NETWORK_INFO,
        SAFE_BLOCKCHAIN_INFO,
        'mainnet',
        checkpoint_hash='00' * 32,
        observed_at=1_777_000_000,
    )
    assert status.checkpoint_verified is False
    assert status.core_safe is False


def test_verified_identity_requires_artifact_digest():
    with pytest.raises(ValueError, match='ARTIFACT_SHA256'):
        BackendIdentity.from_config(
            repository='2miners/Ravencoin',
            commit='b60f50e04f1fba425b28804e61be2694faaf3469',
            evidence='BUILD_IDENTITY_VERIFIED',
        )


def test_ravencoin_configuration_is_coin_local():
    original_bitcoin_daemon = Bitcoin.DAEMON
    original_bitcoin_session = Bitcoin.SESSIONCLS

    configure_ravencoin_coin(TestRavencoin)

    assert TestRavencoin.DAEMON is RavencoinDaemon
    assert TestRavencoin.SESSIONCLS is RavencoinElectrumX
    assert TestRavencoin.KAWPOW_HEIGHT_VALIDATION is True
    assert Bitcoin.DAEMON is original_bitcoin_daemon
    assert Bitcoin.SESSIONCLS is original_bitcoin_session


def test_kawpow_declared_height_is_enforced_on_mainnet():
    configure_ravencoin_coin(TestRavencoin)
    height = KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT

    good_header = _header_with_height(TestRavencoin, height)
    assert TestRavencoin.block_header(good_header, height) == good_header

    bad_header = _header_with_height(TestRavencoin, height - 1)
    with pytest.raises(CoinError, match='nHeight'):
        TestRavencoin.block_header(bad_header, height)


def test_testnet_does_not_claim_mainnet_height_validation():
    configure_ravencoin_coin(TestRavencoinTestnet)
    assert TestRavencoinTestnet.KAWPOW_HEIGHT_VALIDATION is False


def test_session_extension_preserves_existing_legacy_handlers(monkeypatch):
    legacy_version_handler = object()
    legacy_balance_handler = object()

    def fake_base_handlers(self, ptuple):
        self.protocol_tuple = ptuple
        self.request_handlers = {
            'server.version': legacy_version_handler,
            'blockchain.scripthash.get_balance': legacy_balance_handler,
        }
        self.notification_handlers = {}

    monkeypatch.setattr(ElectrumX, 'set_request_handlers', fake_base_handlers)
    session = object.__new__(RavencoinElectrumX)

    for ptuple in ((1, 0), (1, 4, 2), (1, 6), (1, 7)):
        RavencoinElectrumX.set_request_handlers(session, ptuple)
        assert session.request_handlers['server.version'] is legacy_version_handler
        assert (
            session.request_handlers['blockchain.scripthash.get_balance']
            is legacy_balance_handler
        )
        assert (
            session.request_handlers['server.ravencoin_backend']
            == session.phandle_ravencoin_backend
        )


@pytest.mark.asyncio
async def test_daemon_collects_and_caches_sanitized_status(monkeypatch):
    daemon = RavencoinDaemon(
        TestRavencoin,
        'rpc_user:rpc_pass@127.0.0.1:8766',
    )
    calls = {'network': 0, 'chain': 0, 'checkpoint': 0}

    async def send_single(method, params=None):
        if method == 'getnetworkinfo':
            calls['network'] += 1
            return dict(SAFE_NETWORK_INFO)
        if method == 'getblockchaininfo':
            calls['chain'] += 1
            return dict(SAFE_BLOCKCHAIN_INFO)
        assert method == 'getblockhash'
        assert params == (4_487_775,)
        calls['checkpoint'] += 1
        return INCIDENT_CHECKPOINT_HASH

    monkeypatch.setattr(daemon, '_send_single', send_single)

    first = await daemon.ravencoin_backend_status('mainnet', max_age=5)
    second = await daemon.ravencoin_backend_status('mainnet', max_age=5)

    assert first is second
    assert first.core_safe is True
    assert calls == {'network': 1, 'chain': 1, 'checkpoint': 1}
