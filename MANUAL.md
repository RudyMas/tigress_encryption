# Tigress Encryption Library — Programmer's Manual

## Overview

The **Tigress Encryption Library** provides a unified PHP interface for symmetric (AES, Triple DES) and asymmetric (RSA) encryption. It wraps `phpseclib3` with convenience methods for key generation, IV handling, and encryption/decryption.

**Namespace:** `Tigress`  
**PHP requirement:** `>= 8.5`  
**Dependency:** `phpseclib/phpseclib >= 3`

---

## Base Class: `Encryption` (`src/Encryption.php`)

Abstract parent shared by all three cipher classes. Contains four protected properties accessed via getters/setters.

### Properties

| Property | Type | Description |
|---|---|---|
| `$key` | `string` | The encryption key (stored base64-encoded) |
| `$keyPassword` | `mixed` | Optional password for key decryption (RSA) |
| `$iv` | `string` | Initialisation vector (stored raw binary, getter/setter converts to/from base64) |
| `$hash` | `string` | SHA-1 hash of the encrypted payload (set automatically after encryption) |

### Methods

```php
public static function version(): string
```
Returns the library version string (e.g. `'2025.12.09'`).

```php
public function setKey(string $key, mixed $password = false): void
public function getKey(): string
```
Set/get the key. For RSA, pass the optional `$password` to unlock a password-protected private key. The key is stored as-is (for RSA this is the PEM string; for AES/DES this is a base64-encoded random key).

```php
public function setIv(string $iv): void
public function getIv(): string
```
Set/get the initialisation vector. `setIv()` takes a **base64-encoded** IV and decodes it internally. `getIv()` returns the IV **base64-encoded**.

```php
public function setHash(string $hash): void
public function getHash(): string
```
Set/get the SHA-1 hash of the encrypted data. Automatically populated by `encrypt()`.

### Typical workflow

```
setKey() / setIv()   →   encrypt() / decrypt()
            ↑                      ↓
        (keys prepared)      hash stored automatically
```

---

## AES: `EncryptionAES` (`src/EncryptionAES.php`)

Extends `Encryption`. Uses `phpseclib3\Crypt\AES`.

### Key & IV generation

```php
public function createKey(int $bytes = 32): string
```
Returns a cryptographically secure random key **base64-encoded**. Recommended byte sizes:

| Bytes | Bits |
|---|---|
| 16 | 128 |
| 24 | 192 |
| 32 | 256 (default) |

```php
public function createIV(int $bytes = 16): string
```
Returns a random IV **base64-encoded** (16 bytes recommended for AES).

### Encrypt / Decrypt

```php
public function encrypt(string $data, string $encryptionMode = 'cbc'): string
public function decrypt(string $data, string $encryptionMode = 'cbc'): string
```

- `$data` — plaintext (encrypt) or base64 ciphertext (decrypt).
- `$encryptionMode` — any mode supported by phpseclib3 AES (e.g. `'cbc'`, `'ecb'`, `'cfb'`, `'ctr'`).
- Returns **base64-encoded** ciphertext from `encrypt()`, raw plaintext from `decrypt()`.
- When mode is **not** `'ecb'`, an IV is required. If `$this->iv` is empty, `encrypt()` generates a random 16-byte IV automatically.
- After encryption the SHA-1 hash of the raw binary ciphertext is stored in `$this->hash`.

### Usage example

```php
use Tigress\EncryptionAES;

$aes = new EncryptionAES();
$key = $aes->createKey();          // 256-bit key (base64)
$iv  = $aes->createIV();           // 128-bit IV  (base64)

$aes->setKey($key);
$aes->setIv($iv);

$ciphertext = $aes->encrypt('Hello, world!');
$plaintext  = $aes->decrypt($ciphertext);

$hash = $aes->getHash();           // SHA-1 of ciphertext
```

---

## Triple DES: `EncryptionDES` (`src/EncryptionDES.php`)

Extends `Encryption`. Uses `phpseclib3\Crypt\TripleDES`. Despite its name, this is **Triple DES** (3DES), not single DES.

### Key generation

```php
public function createKey(int $bytes = 24): string
```
Returns a base64-encoded key. Triple DES conventionally uses a 24-byte (192-bit) key. Different byte sizes may or may not be supported depending on the phpseclib3 backend.

### Encrypt / Decrypt

```php
public function encrypt(string $data, string $encryptionMode = 'cbc'): string
public function decrypt(string $data, string $encryptionMode = 'cbc'): string
```

- Same interface as AES.
- When mode is **not** `'ecb'`, an IV is required. DES uses an **8-byte** IV (not 16). If `$this->iv` is empty, `encrypt()` generates a random 8-byte IV automatically.
- Returns base64-encoded ciphertext; raw plaintext on decrypt.

### Usage example

```php
use Tigress\EncryptionDES;

$des = new EncryptionDES();
$key = $des->createKey();          // 24-byte key (base64)
$iv  = base64_encode(random_bytes(8));

$des->setKey($key);
$des->setIv($iv);

$ciphertext = $des->encrypt('Sensitive data');
$plaintext  = $des->decrypt($ciphertext);
```

---

## RSA: `EncryptionRSA` (`src/EncryptionRSA.php`)

Extends `Encryption`. Uses `phpseclib3\Crypt\RSA`.

### Key pair generation

```php
public function createPrivateKey(int $bits, string $type = 'PKCS1', mixed $password = false): string
```
Generates a new RSA private key.

| Param | Description |
|---|---|
| `$bits` | Key size in bits (e.g. 2048, 4096) |
| `$type` | Output format — `'PKCS1'` (default), `'PKCS8'`, `'OpenSSH'`, `'XML'`, `'PuTTY'` |
| `$password` | Optional password to encrypt the private key (false = no password) |

Returns the private key as a PEM string (or other chosen format).

```php
public function createPublicKey(string $privateKey, string $type = 'PKCS1', mixed $password = false): string
```
Derives the public key from a private key string.

| Param | Description |
|---|---|
| `$privateKey` | The private key PEM string |
| `$type` | Output format (same options as above) |
| `$password` | Password if the private key is encrypted |

Returns the public key string.

### Encrypt / Decrypt

```php
public function encrypt(string $data): string
public function decrypt(string $data): string
```

- `encrypt()` — expects the **public key** loaded via `setKey()`; returns base64-encoded ciphertext.
- `decrypt()` — expects the **private key** loaded via `setKey()` (with password if applicable); returns raw plaintext.
- If the ciphertext is corrupted or too short, `decrypt()` returns the string `'Data is corrupted!'` (caught via `LengthException`).
- Empty input returns an empty string on decrypt.

### Usage example

```php
use Tigress\EncryptionRSA;

$rsa = new EncryptionRSA();

// Generate key pair
$privateKey = $rsa->createPrivateKey(2048, 'PKCS8', 'my-secret-password');
$publicKey  = $rsa->createPublicKey($privateKey, 'PKCS8', 'my-secret-password');

// Encrypt with public key
$rsa->setKey($publicKey);
$ciphertext = $rsa->encrypt('Confidential message');

// Decrypt with private key
$rsa->setKey($privateKey, 'my-secret-password');
$plaintext  = $rsa->decrypt($ciphertext);
```

---

## Installation

```bash
composer require tigress/encryption
```

## Error handling

| Exception | Raised by | When |
|---|---|---|
| `RandomException` | `createKey()`, `encrypt()` (AES/DES) | OS randomness source fails |
| `LengthException` | `decrypt()` (RSA) | Ciphertext is too short to decrypt — caught internally, returns error string |

For phpseclib3-level errors (wrong key, wrong IV size, unsupported mode), the underlying exceptions bubble up uncaught.

## Security notes

- **IV handling:** For CBC/CFB/CTR/OFB modes you **must** use a fresh, random IV for every encryption. Reusing an IV with the same key breaks confidentiality. The IV need not be secret but should be stored alongside the ciphertext.
- **AES key sizes:** 128-bit is secure; 256-bit provides a wider security margin. Avoid 192-bit unless required for interoperability.
- **DES:** Triple DES is legacy. For new projects prefer AES. DES uses 8-byte IVs and 24-byte keys.
- **RSA:** Use ≥ 2048-bit keys. Password-protect private keys in storage. RSA encrypts only small payloads (key-size-dependent).
- **SHA-1 hash:** The stored hash uses SHA-1, which is cryptographically weakened. It is suitable for integrity checks against accidental corruption only, not against deliberate tampering.
- **ECB mode:** Avoid ECB mode unless you fully understand the security implications (deterministic, leaks patterns).
