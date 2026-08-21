# Copyright (c) 2026, the ElectrumX-RVN community maintainers
#
# The MIT License (MIT). See LICENCE for details.

'''Ravencoin-only backend capability for ElectrumX.

This module is intentionally isolated from the generic ElectrumX server paths.
It is activated by :mod:`electrumx.server.env` only for the Ravencoin coin
class.  Legacy Electrum protocol handlers and every other coin keep using the
existing generic Daemon and ElectrumX classes unchanged.
'''

import asyncio
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import time

import electrumx
from electrumx.lib import util
from electrumx.lib.coins import CoinError
from electrumx.lib.hash import hash_to_hex_str
from electrumx.server.daemon import Daemon
from electrumx.server.session import ElectrumX


MINIMUM_SAFE_CORE = (4, 8, 0, 0)
MINIMUM_SAFE_CORE_STRING = '4.8.0'
INCIDENT_CHECKPOINT_HEIGHT = 4_487_775
INCIDENT_CHECKPOINT_HASH = (
    '000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd'
)
KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT = 4_487_776
SAFETY_PROFILE = 'rvn-consensus-2026-08-v1'

# Exact official RavenProject release artifacts.  A version string is never
# enough to select one of these entries: automatic identity is enabled only
# after hashing the executable itself.
OFFICIAL_RAVEND_BUILDS = {
    '885f6670c819e3a48339bbc596f1a224fe41af21ae7a0db57b2ebca700d050ea': {
        'repository': 'RavenProject/Ravencoin',
        'tag': 'v4.8.0',
        'commit': '22549129888d02e0e08fcdb9f96f3c699167e774',
        'artifact_sha256': (
            'cb359b6a5b42e47068cd655231484fcc'
            '763d2f79eae5ea318b029c704a4dc020'
        ),
        'architecture': 'x86_64-linux-gnu',
    },
}


class IdentityEvidence:
    '''How strongly the operator can identify the running Ravencoin Core build.'''

    BUILD_VERIFIED = 'BUILD_IDENTITY_VERIFIED'
    ATTESTED = 'BUILD_IDENTITY_ATTESTED'
    VERSION_ONLY = 'VERSION_ONLY'
    UNKNOWN = 'UNKNOWN'
    ALL = (BUILD_VERIFIED, ATTESTED, VERSION_ONLY, UNKNOWN)


@dataclass(frozen=True)
class BackendIdentity:
    '''Operator-supplied identity of the configured Ravencoin Core build.'''

    repository: str | None = None
    tag: str | None = None
    commit: str | None = None
    artifact_sha256: str | None = None
    binary_sha256: str | None = None
    architecture: str | None = None
    evidence: str = IdentityEvidence.VERSION_ONLY

    @classmethod
    def from_config(
            cls,
            repository='',
            tag='',
            commit='',
            artifact_sha256='',
            evidence='',
    ):
        repository = (repository or '').strip() or None
        tag = (tag or '').strip() or None
        commit = (commit or '').strip().lower() or None
        artifact_sha256 = (artifact_sha256 or '').strip().lower() or None
        declared = (evidence or '').strip().upper() or None

        if commit is not None and not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('RAVENCOIN_SOURCE_COMMIT must be a 40-character hex commit')
        if artifact_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', artifact_sha256):
            raise ValueError('RAVENCOIN_ARTIFACT_SHA256 must be a 64-character hex digest')
        if declared is not None and declared not in IdentityEvidence.ALL:
            raise ValueError(f'unknown RAVENCOIN_IDENTITY_EVIDENCE {declared!r}')

        # A partial identity must not look stronger than version-only evidence.
        if repository is None or commit is None:
            return cls(evidence=IdentityEvidence.VERSION_ONLY)

        if declared == IdentityEvidence.BUILD_VERIFIED:
            raise ValueError(
                'BUILD_IDENTITY_VERIFIED is reserved for automatic executable '
                'hash verification'
            )

        return cls(
            repository=repository,
            tag=tag,
            commit=commit,
            artifact_sha256=artifact_sha256,
            evidence=declared or IdentityEvidence.ATTESTED,
        )

    @classmethod
    def from_official_binary(cls, path):
        '''Identify one exact official build by hashing the executable bytes.'''
        path = Path(path)
        try:
            digest = _sha256_file(path)
        except OSError as exc:
            raise ValueError(f'cannot read running Ravencoin Core binary {path}: {exc}') from exc

        release = OFFICIAL_RAVEND_BUILDS.get(digest)
        if release is None:
            raise ValueError(
                f'Ravencoin Core binary {path} has unrecognized SHA-256 {digest}'
            )
        return cls(
            repository=release['repository'],
            tag=release['tag'],
            commit=release['commit'],
            artifact_sha256=release['artifact_sha256'],
            binary_sha256=digest,
            architecture=release['architecture'],
            evidence=IdentityEvidence.BUILD_VERIFIED,
        )

    @classmethod
    def from_pid_file(cls, pid_file, proc_root='/proc'):
        '''Hash the executable of the live process named by a ravend pidfile.'''
        pid_file = Path(pid_file)
        try:
            literal = pid_file.read_text(encoding='ascii').strip()
        except OSError as exc:
            raise ValueError(f'cannot read Ravencoin Core pidfile {pid_file}: {exc}') from exc
        if not re.fullmatch(r'[1-9][0-9]*', literal):
            raise ValueError(f'Ravencoin Core pidfile {pid_file} is malformed')
        return cls.from_official_binary(Path(proc_root) / literal / 'exe')

    def public_dict(self):
        result = {'evidence': self.evidence}
        if self.repository is not None and self.commit is not None:
            result['sourceRepository'] = self.repository
            result['sourceCommit'] = self.commit
            if self.tag is not None:
                result['sourceTag'] = self.tag
            if self.artifact_sha256 is not None:
                result['artifactSha256'] = self.artifact_sha256
            if self.binary_sha256 is not None:
                result['binarySha256'] = self.binary_sha256
            if self.architecture is not None:
                result['architecture'] = self.architecture
        return result


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def detect_unique_official_ravend(proc_root='/proc'):
    '''Return verified identity for one visible live ravend, else VERSION_ONLY.

    Discovery is deliberately fail-closed.  No identity is selected if zero or
    multiple accessible ``ravend`` processes exist, or if the sole executable
    is not an exact known official build.
    '''
    proc_root = Path(proc_root)
    candidates = []
    ravend_processes = 0
    try:
        processes = list(proc_root.iterdir())
    except OSError:
        return BackendIdentity()

    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            if (process / 'comm').read_text(encoding='ascii').strip() != 'ravend':
                continue
            ravend_processes += 1
            candidates.append(BackendIdentity.from_official_binary(process / 'exe'))
        except (OSError, UnicodeError, ValueError):
            # An inaccessible or unknown process cannot contribute identity.
            continue
    return (
        candidates[0]
        if ravend_processes == 1 and len(candidates) == 1
        else BackendIdentity()
    )


def parse_core_version(version):
    '''Decode Ravencoin Core's integer version; e.g. 4080000 -> (4, 8, 0, 0).'''
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError(f'invalid Ravencoin Core version: {version!r}')
    major, remainder = divmod(version, 1_000_000)
    minor, remainder = divmod(remainder, 10_000)
    patch, build = divmod(remainder, 100)
    return major, minor, patch, build


def core_version_string(version_tuple):
    major, minor, patch, build = version_tuple
    base = f'{major}.{minor}.{patch}'
    return f'{base}.{build}' if build else base


def expected_daemon_chain(electrum_network):
    mapping = {'mainnet': 'main', 'testnet': 'test', 'regtest': 'regtest'}
    try:
        return mapping[electrum_network]
    except KeyError as exc:
        raise ValueError(f'unsupported Ravencoin network: {electrum_network!r}') from exc


@dataclass(frozen=True)
class RavencoinBackendStatus:
    version_number: int
    version_tuple: tuple
    subversion: str
    network: str
    blocks: int
    headers: int
    initial_block_download: bool | None
    version_safe: bool
    network_matches: bool
    synchronized: bool
    checkpoint_known: bool
    checkpoint_verified: bool
    observed_at: int

    @property
    def core_safe(self):
        # Synchronization is intentionally reported separately, matching the
        # Electrum-Ravencoin evidence contract.
        return self.version_safe and self.network_matches and self.checkpoint_known

    def public_dict(self, server_version, identity=None, kawpow_height_validation=False):
        identity = identity or BackendIdentity()
        return {
            'server': 'ElectrumX',
            'serverVersion': server_version,
            'backend': {
                'name': 'Ravencoin Core',
                'version': core_version_string(self.version_tuple),
                'versionNumber': self.version_number,
                'subversion': self.subversion,
                'network': self.network,
                'blocks': self.blocks,
                'headers': self.headers,
                'initialBlockDownload': self.initial_block_download,
                'identity': identity.public_dict(),
            },
            'compatibility': {
                'minimumSafeCore': MINIMUM_SAFE_CORE_STRING,
                'safetyProfile': SAFETY_PROFILE,
                'identityEvidence': identity.evidence,
                'coreSafe': self.core_safe,
                'networkMatches': self.network_matches,
                'backendSynchronized': self.synchronized,
                'kawpowHeightValidation': bool(kawpow_height_validation),
                'checkpoint4487775': self.checkpoint_verified,
            },
            'observedAt': self.observed_at,
        }


def evaluate_backend(
        network_info,
        blockchain_info,
        electrum_network,
        checkpoint_hash=None,
        observed_at=None,
):
    '''Build sanitized backend evidence from Ravencoin Core RPC results.'''
    version_number = network_info.get('version')
    version_tuple = parse_core_version(version_number)

    subversion = network_info.get('subversion')
    if not isinstance(subversion, str) or not subversion:
        raise ValueError('Ravencoin Core subversion is missing or malformed')

    network = blockchain_info.get('chain')
    blocks = blockchain_info.get('blocks')
    headers = blockchain_info.get('headers')
    ibd = blockchain_info.get('initialblockdownload')

    if not isinstance(network, str) or not network:
        raise ValueError('Ravencoin Core network is missing or malformed')
    if isinstance(blocks, bool) or not isinstance(blocks, int) or blocks < 0:
        raise ValueError('Ravencoin Core block height is missing or malformed')
    if isinstance(headers, bool) or not isinstance(headers, int) or headers < blocks:
        raise ValueError('Ravencoin Core header height is missing or malformed')
    if ibd not in (True, False, None):
        raise ValueError('Ravencoin Core IBD state is malformed')

    network_matches = network == expected_daemon_chain(electrum_network)
    version_safe = version_tuple >= MINIMUM_SAFE_CORE
    checkpoint_required = network == 'main' and blocks >= INCIDENT_CHECKPOINT_HEIGHT
    checkpoint_matches = (
        isinstance(checkpoint_hash, str)
        and checkpoint_hash.lower() == INCIDENT_CHECKPOINT_HASH
    )
    checkpoint_known = not checkpoint_required or checkpoint_matches
    checkpoint_verified = checkpoint_required and checkpoint_matches
    synchronized = ibd is not True and blocks == headers

    return RavencoinBackendStatus(
        version_number=version_number,
        version_tuple=version_tuple,
        subversion=subversion,
        network=network,
        blocks=blocks,
        headers=headers,
        initial_block_download=ibd,
        version_safe=version_safe,
        network_matches=network_matches,
        synchronized=synchronized,
        checkpoint_known=checkpoint_known,
        checkpoint_verified=checkpoint_verified,
        observed_at=int(time.time() if observed_at is None else observed_at),
    )


class RavencoinDaemon(Daemon):
    '''Daemon adapter used only by Ravencoin instances.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ravencoin_backend_status = None
        self._ravencoin_backend_checked = 0.0
        self._ravencoin_backend_lock = asyncio.Lock()

    async def ravencoin_backend_status(self, electrum_network, max_age=5):
        '''Return fresh/cached status of the configured ravend.'''
        now = time.monotonic()
        if (
            self._ravencoin_backend_status is not None
            and max_age > 0
            and now - self._ravencoin_backend_checked <= max_age
        ):
            return self._ravencoin_backend_status

        async with self._ravencoin_backend_lock:
            now = time.monotonic()
            if (
                self._ravencoin_backend_status is not None
                and max_age > 0
                and now - self._ravencoin_backend_checked <= max_age
            ):
                return self._ravencoin_backend_status

            network_info, blockchain_info = await asyncio.gather(
                self._send_single('getnetworkinfo'),
                self._send_single('getblockchaininfo'),
            )

            checkpoint_hash = None
            if (
                blockchain_info.get('chain') == 'main'
                and blockchain_info.get('blocks', -1) >= INCIDENT_CHECKPOINT_HEIGHT
            ):
                checkpoint_hash = await self._send_single(
                    'getblockhash', (INCIDENT_CHECKPOINT_HEIGHT,)
                )

            status = evaluate_backend(
                network_info,
                blockchain_info,
                electrum_network,
                checkpoint_hash=checkpoint_hash,
            )
            self._ravencoin_backend_status = status
            self._ravencoin_backend_checked = time.monotonic()
            return status


class RavencoinElectrumX(ElectrumX):
    '''Add one optional Ravencoin RPC without changing existing handlers.'''

    def set_request_handlers(self, ptuple):
        # This preserves every protocol-version-dependent handler configured by
        # ElectrumX, including handlers used by older Electrum clients.
        super().set_request_handlers(ptuple)
        self.request_handlers['server.ravencoin_backend'] = self.phandle_ravencoin_backend

    async def phandle_ravencoin_backend(self):
        self.bump_cost(0.5)
        status = await self.session_mgr.daemon.ravencoin_backend_status(
            self.coin.NET,
            self.env.ravencoin_backend_info_max_age,
        )
        return status.public_dict(
            server_version=electrumx.version,
            identity=self.env.ravencoin_backend_identity,
            kawpow_height_validation=getattr(
                self.coin, 'KAWPOW_HEIGHT_VALIDATION', False
            ),
        )


def _ravencoin_block_header(cls, block, height):
    '''Return a Ravencoin header after incident-era invariant checks.'''
    expected_size = cls.static_header_len(height)
    header = block[:expected_size]
    if len(header) != expected_size:
        raise CoinError(
            f'Ravencoin header at height {height} is {len(header)} bytes, '
            f'expected {expected_size}'
        )

    if cls.NET == 'mainnet' and height >= KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT:
        declared_height = util.unpack_le_uint32_from(header, 76)[0]
        if declared_height != height:
            raise CoinError(
                f'Ravencoin KAWPOW header at chain height {height} declares '
                f'nHeight={declared_height}'
            )

    if cls.NET == 'mainnet' and height == INCIDENT_CHECKPOINT_HEIGHT:
        actual_hash = hash_to_hex_str(cls.header_hash_rev(header))
        if actual_hash != INCIDENT_CHECKPOINT_HASH:
            raise CoinError(
                f'Ravencoin incident checkpoint mismatch at {height}: '
                f'{actual_hash} != {INCIDENT_CHECKPOINT_HASH}'
            )

    return header


def configure_ravencoin_coin(coin):
    '''Attach the isolated Ravencoin daemon/session and header checks.'''
    if getattr(coin, 'NAME', None) != 'Ravencoin':
        raise ValueError('Ravencoin backend capability can only configure Ravencoin')

    coin.DAEMON = RavencoinDaemon
    coin.SESSIONCLS = RavencoinElectrumX
    coin.INCIDENT_CHECKPOINT_HEIGHT = INCIDENT_CHECKPOINT_HEIGHT
    coin.INCIDENT_CHECKPOINT_HASH = INCIDENT_CHECKPOINT_HASH
    coin.KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT = KAWPOW_HEIGHT_ENFORCEMENT_HEIGHT
    coin.KAWPOW_HEIGHT_VALIDATION = coin.NET == 'mainnet'

    # Setting this classmethod is intentionally local to the selected Ravencoin
    # class. No generic Coin or non-RVN protocol behavior is changed.
    coin.block_header = classmethod(_ravencoin_block_header)
    return coin
