"""本人の在席を Windows Hello の署名で確かめる。

鍵は Windows Hello（TPM）内で作られ、秘密鍵は取り出せない。署名のたびに本人の
PIN・生体認証が要るため、AIだけでは承認を作れない。PC上の検証は公開鍵を毎回 Windows
から読み、ファイルの公開鍵を信頼しない。例外は配送の関門（tools/delivery_gate.py）で、CIには
Windows が無いため、既定ブランチ側の system/owner/owner-key.json（変更には本人の署名が要る）を使う。

限界: 同じユーザーのシェルを持つAIは、この検証コード自体を書き換えられる。
その改変は package.manifest.json とGitの差分で検出する前提で、OSの強制隔離ではない。
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import subprocess

CREDENTIAL = 'Asteria-Owner'
POWERSHELL = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
_PRELUDE = r'''
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null=[Windows.Security.Credentials.KeyCredentialManager,Windows.Security.Credentials,ContentType=WindowsRuntime]
$null=[Windows.Security.Cryptography.CryptographicBuffer,Windows.Security.Cryptography,ContentType=WindowsRuntime]
$asTask=([System.WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'})[0]
function Await($op,[Type]$t){$k=$asTask.MakeGenericMethod($t).Invoke($null,@($op));$k.Wait(-1)|Out-Null;$k.Result}
$M=[Windows.Security.Credentials.KeyCredentialManager]
function Open(){$r=Await ($M::OpenAsync('%s')) ([Windows.Security.Credentials.KeyCredentialRetrievalResult]);if($r.Status -ne 'Success'){throw ('credential_'+$r.Status)};$r.Credential}
function B64($buf){[Windows.Security.Cryptography.CryptographicBuffer].GetMethod('EncodeToBase64String').Invoke($null,@($buf))}
''' % CREDENTIAL

_SCRIPTS = {
    'public': _PRELUDE + r'''B64 ((Open).RetrievePublicKey())''',
    'create': _PRELUDE + r'''$r=Await ($M::RequestCreateAsync('%s',[Windows.Security.Credentials.KeyCredentialCreationOption]::FailIfExists)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult]);if($r.Status -ne 'Success'){throw ('create_'+$r.Status)};B64 ($r.Credential.RetrievePublicKey())''' % CREDENTIAL,
    'sign': _PRELUDE + r'''$data=[Windows.Security.Cryptography.CryptographicBuffer]::DecodeFromBase64String($env:ASTERIA_SIGN_MESSAGE);$r=Await ([Windows.Security.Credentials.KeyCredential].GetMethod('RequestSignAsync').Invoke((Open),@($data))) ([Windows.Security.Credentials.KeyCredentialOperationResult]);if($r.Status -ne 'Success'){throw ('sign_'+$r.Status)};B64 $r.Result''',
}


class OwnerPresenceError(Exception):
    pass


def _run(action: str, message: bytes | None = None, timeout=180) -> str:
    env = {k: v for k, v in os.environ.items() if k.upper() in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PATH', 'USERNAME', 'COMPUTERNAME')}
    if message is not None:
        env['ASTERIA_SIGN_MESSAGE'] = base64.b64encode(message).decode()
    # 公開鍵の読取りだけ窓なし。作成・署名は本人がWindows Helloの画面で確認する。
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' and action == 'public' else {}
    script = '[Console]::OutputEncoding=[Text.Encoding]::UTF8;' + _SCRIPTS[action]
    result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout, env=env, **options)
    if result.returncode != 0:
        detail = (result.stderr or '').strip().splitlines()
        found = next((line.strip() for line in detail if 'credential_' in line or 'sign_' in line or 'create_' in line), None)
        raise OwnerPresenceError(found or ('windows_hello_failed: ' + (detail[0][:200] if detail else 'no detail')))
    return result.stdout.strip()


def _der(data: bytes, pos: int):
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    return tag, data[pos:pos + length], pos + length


def rsa_public_key(spki: bytes) -> tuple[int, int]:
    """X.509 SubjectPublicKeyInfo(DER) から RSA の (n, e) を取り出す。"""
    tag, body, _ = _der(spki, 0)
    if tag != 0x30:
        raise OwnerPresenceError('invalid_public_key')
    _, _, pos = _der(body, 0)                 # AlgorithmIdentifier
    tag, bits, _ = _der(body, pos)
    if tag != 0x03 or bits[:1] != b'\0':
        raise OwnerPresenceError('invalid_public_key')
    tag, seq, _ = _der(bits[1:], 0)
    tag_n, n, pos = _der(seq, 0)
    tag_e, e, _ = _der(seq, pos)
    if tag != 0x30 or tag_n != 0x02 or tag_e != 0x02:
        raise OwnerPresenceError('invalid_public_key')
    return int.from_bytes(n, 'big'), int.from_bytes(e, 'big')


_SHA256_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')


def rsa_verify(public: tuple[int, int], message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 / SHA-256 の検証。"""
    n, e = public
    size = (n.bit_length() + 7) // 8
    if len(signature) != size or size < 256:
        return False
    em = pow(int.from_bytes(signature, 'big'), e, n).to_bytes(size, 'big')
    digest = _SHA256_PREFIX + hashlib.sha256(message).digest()
    expected = b'\x00\x01' + b'\xff' * (size - len(digest) - 3) + b'\x00' + digest
    return hmac.compare_digest(em, expected)


def public_key() -> tuple[int, int]:
    return rsa_public_key(base64.b64decode(_run('public', timeout=30)))


def create() -> str:
    """本人がWindows Helloで確認して鍵を作る。既にあれば失敗する。"""
    return _run('create')


def sign(message: bytes) -> str:
    """本人がWindows Helloで確認して署名する。"""
    return _run('sign', message)


def verifier():
    """Windows Hello の鍵があれば検証関数を返す。無ければ None。"""
    try:
        key = public_key()
    except (OwnerPresenceError, OSError, ValueError, subprocess.TimeoutExpired):
        return None

    def verify(message: bytes, signature: str) -> bool:
        try:
            raw = base64.b64decode(signature, validate=True)
        except (ValueError, TypeError):
            return False
        return rsa_verify(key, message, raw)
    return verify


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


GRANT_PREFIX = b'ASTERIA-OWNER-GRANT-v1\0'
GRANT_FIELDS = {'kind', 'subject_sha256', 'issued_at', 'expires_at', 'nonce', 'owner_note', 'signature'}


def make_grant(kind: str, subject_sha256: str, note: str, seconds: int = 1800, signer=sign) -> dict:
    """外部送信・課金などの本人承認。対象（subject）のハッシュ1つだけに効く。"""
    import secrets
    from datetime import datetime, timedelta, timezone
    if not 8 <= len(note) <= 2000 or not 1 <= seconds <= 3600:
        raise OwnerPresenceError('invalid_grant_request')
    now = datetime.now(timezone.utc)
    grant = {'kind': kind, 'subject_sha256': subject_sha256, 'owner_note': note, 'nonce': secrets.token_hex(16),
             'issued_at': now.isoformat(), 'expires_at': (now + timedelta(seconds=seconds)).isoformat()}
    grant['signature'] = signer(GRANT_PREFIX + canonical(grant))
    return grant


def check_grant(grant, kind: str, subject_sha256: str, verify=None) -> None:
    """承認が本人の署名つきで、この種類・この対象・有効期間内であることを確かめる。"""
    from datetime import datetime, timezone
    if not isinstance(grant, dict) or set(grant) != GRANT_FIELDS:
        raise OwnerPresenceError('owner_grant_required')
    if grant['kind'] != kind or grant['subject_sha256'] != subject_sha256:
        raise OwnerPresenceError('owner_grant_scope_mismatch')
    try:
        issued = datetime.fromisoformat(grant['issued_at'])
        expires = datetime.fromisoformat(grant['expires_at'])
    except (TypeError, ValueError):
        raise OwnerPresenceError('owner_grant_invalid_time') from None
    now = datetime.now(timezone.utc)
    if issued.tzinfo is None or not issued <= expires or (expires - issued).total_seconds() > 3600 or not issued.timestamp() - 30 <= now.timestamp() < expires.timestamp():
        raise OwnerPresenceError('owner_grant_expired_or_future')
    verify = verify or verifier()
    if verify is None:
        raise OwnerPresenceError('owner_key_not_configured')
    unsigned = {k: v for k, v in grant.items() if k != 'signature'}
    if not isinstance(grant['signature'], str) or not verify(GRANT_PREFIX + canonical(unsigned), grant['signature']):
        raise OwnerPresenceError('invalid_owner_signature')
