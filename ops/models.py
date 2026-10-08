"""Wire contracts and errors shared by role HTTP services."""
from dataclasses import dataclass
from typing import TypedDict


class APIError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = 'invalid_request'):
        super().__init__(message)
        self.status, self.code = status, code


@dataclass(frozen=True)
class ChainScope:
    chain_id: int
    registry: str
    license: str
    deployment_block: int
    revision: str


@dataclass(frozen=True)
class WalletSession:
    address: str
    scope: ChainScope
    expires_at: int


@dataclass(frozen=True)
class HTTPReply:
    status: int
    headers: dict[str, str]
    body: bytes


PackagePreview = TypedDict('PackagePreview', {
    'packageId': str, 'publisher': str, 'manifest': dict, 'files': list,
    'codeHash': str, 'metadataHash': str, 'source': str,
})
PreparedTx = TypedDict('PreparedTx', {
    'id': str, 'scopeRevision': str, 'chainId': int, 'from': str,
    'to': str | None, 'data': str, 'value': str,
    'estimatedGas': str | None, 'estimatedFee': str | None,
})
TxConfirmation = TypedDict('TxConfirmation', {
    'preparedId': str, 'txHash': str, 'status': str,
    'blockNumber': int | None, 'error': str | None,
})
