# Project Plan & Conceptual Blueprint (`brain.md`)

## Project Title
**Secure Key Management for AI/ML Applications with Automatic Key Rotation**  
*College DSP (Digital Signal Processing / Data Science & Privacy) Micro Project*

---

## 1. Problem Understanding
Modern Artificial Intelligence and Machine Learning (AI/ML) systems handle sensitive data such as:
- Electronic health and diagnostic records (e.g., patient condition, lab results).
- Facial and biometric embeddings.
- Confidential financial records and credit ratings.
- Proprietary model weights and embeddings.

If static encryption keys are used:
1. **Prolonged Exposure Window**: If a secret key leaks or is compromised, an attacker can decrypt historical and future sensitive data indefinitely.
2. **Key Wear-out / Cryptanalysis**: Repeatedly encrypting high volumes of inference requests under the identical key provides cryptanalysts with known ciphertext samples.
3. **Manual Overhead & Human Error**: Manual key rotation is rarely executed on time, causing security gaps.

---

## 2. Research Motivation
Most basic student encryption projects demonstrate simple one-time encryption using a hardcoded key. In real-world security engineering (e.g., NIST SP 800-57 guidelines), cryptographic keys must have a strictly governed **cryptographic lifecycle**.

The primary motivation of this micro project is to implement **Automatic Time-Based Key Rotation** as the core innovation:
- Keys automatically expire after a predefined duration ($\tau = 60$ seconds for live demonstration).
- Upon expiration, existing sensitive data is re-encrypted with the new key without data loss.
- The previous key is marked as **REVOKED** and rejected for any new encryption operations.

---

## 3. Cryptographic Key Lifecycle
The application strictly demonstrates all 6 fundamental phases of a cryptographic key's life:

```
[ 1. Key Generation ] ───► Secure 256-bit Fernet Symmetric Key
          │
          ▼
[ 2. Key Storage ]    ───► Stored locally in data/key.json with Metadata (Fingerprint ID)
          │
          ▼
[ 3. Key Usage ]      ───► Encryption (C = E(K, D)) & Decryption (D = E⁻¹(K, C))
          │
          ▼
[ 4. Key Rotation ]   ───► Triggered automatically when Time >= 60s
          │
          ▼
[ 5. Key Revocation ] ───► Old Key is designated REVOKED; Cannot decrypt newly encrypted data
          │
          ▼
[ 6. Key Deletion ]   ───► Cryptographic Erasure; Inactive key prevents any further decryption
```

---

## 4. System Architecture
The prototype is deliberately lightweight, standalone, and built with zero heavy external frameworks:

```
┌────────────────────────────────────────────────────────┐
│                   Web Browser UI                       │
│    Dashboard (HTML5 + CSS3 + Vanilla Fetch JS)         │
│  - Key Status Card (Active, Revoked, Age Countdown)    │
│  - Sensitive Data Card (Patient ID Demo Text)          │
│  - Key Management Controls (Generate, Rotate, Delete)  │
│  - Security Test Card (Unauthorized Intrusion Demo)    │
│  - Real-time Activity Log                              │
└──────────────────────────▲─────────────────────────────┘
                           │ HTTP / JSON REST APIs
┌──────────────────────────▼─────────────────────────────┐
│                    Flask Web Server                    │
│                        (app.py)                        │
└──────────────────────────▲─────────────────────────────┘
                           │ Internal Function Calls
┌──────────────────────────▼─────────────────────────────┐
│              Key Lifecycle Engine                      │
│                 (key_manager.py)                       │
│   - generate_key()           - encrypt_data()          │
│   - load_key_store()         - decrypt_data()          │
│   - rotate_key()             - delete_key()            │
│   - check_key_expiry()       - test_unauthorized_access│
└──────────────┬──────────────────────────┬──────────────┘
               │                          │
       Reads / Writes             Reads / Writes
               ▼                          ▼
    ┌────────────────────┐      ┌────────────────────┐
    │   data/key.json    │      │encrypted_data.txt  │
    │  (Key Metadata)    │      │   (Ciphertext)     │
    └────────────────────┘      └────────────────────┘
```

---

## 5. Mathematical Model
Let:
- $D$ = Sensitive Original Plaintext Data
- $K$ = Symmetric Secret Encryption Key ($K \in \{0, 1\}^{256}$)
- $C$ = Ciphertext output ($C \in \{0, 1\}^*$)
- $E(K, D)$ = Fernet Encryption Function (AES-128-CBC + HMAC-SHA256 authenticated encryption)
- $E^{-1}(K, C)$ = Fernet Decryption and Verification Function
- $T_{created}$ = Unix timestamp of key generation
- $T_{current}$ = Current system timestamp
- $\tau$ = Key lifetime interval ($\tau = 60\text{ seconds}$)

### 5.1 Encryption
$$C = E(K, D)$$
The plaintext data $D$ is encrypted using key $K$ to produce authenticated ciphertext $C$.

### 5.2 Decryption
$$D = E^{-1}(K, C)$$
Decryption recovers $D$ if and only if $K$ is authentic and $C$ has not been tampered with.

### 5.3 Key Generation
$$K = \text{Random}(256\text{ bits})$$
Generated via OS cryptographically secure pseudorandom number generator (`os.urandom`).

### 5.4 Automatic Rotation Condition
$$\text{Condition: } (T_{current} - T_{created}) \ge \tau$$
When this condition evaluates to **True**:
1. Decrypt existing ciphertext: $D = E^{-1}(K_{old}, C_{old})$
2. Generate fresh key: $K_{new} = \text{Random}(256\text{ bits})$
3. Re-encrypt data: $C_{new} = E(K_{new}, D)$
4. Revoke old key: $\text{Status}(K_{old}) \leftarrow \text{REVOKED}$
5. Activate new key: $\text{Status}(K_{new}) \leftarrow \text{ACTIVE}$

---

## 6. Modules and File Breakdown
- `app.py`: Flask application providing routing and REST API endpoints (`/api/status`, `/api/generate-key`, `/api/encrypt`, `/api/decrypt`, `/api/rotate`, `/api/delete-key`, `/api/test-wrong-key`).
- `key_manager.py`: Core cryptographic logic using Python's `cryptography.fernet` library.
- `templates/index.html`: Clean HTML5 dashboard with cards, countdown bar, and activity log.
- `static/style.css`: Light, modern CSS stylesheet adhering to professional dashboard aesthetics.
- `data/key.json`: Local storage for current active key, revoked keys history, and rotation count.
- `data/encrypted_data.txt`: Local storage for ciphertext.
- `pyproject.toml` & `uv.lock`: Modern package configuration and dependency lockfile managed via `uv`.

---

## 7. Implementation Steps
1. **Environment Setup**: Initialized virtual environment using `uv` with `flask` and `cryptography`.
2. **Directory Structure**: Created standard Flask structure (`templates/`, `static/`, `data/`).
3. **Core Functions**: Implemented `key_manager.py` with standalone functions avoiding complex OOP boilerplate.
4. **Re-encryption on Rotation**: Implemented fail-safe rotation logic where data is decrypted using $K_{old}$ and re-encrypted with $K_{new}$ so data is never lost.
5. **Security Test Endpoint**: Implemented wrong-key generation to deliberately produce `InvalidToken` exceptions to demonstrate defense against unauthorized access.
6. **Frontend Integration**: Built responsive UI with live 2-second status polling and progress bar.

---

## 8. Automatic Key Rotation Logic
```python
if current_time - key_creation_time >= KEY_LIFETIME:
    # 1. Decrypt existing ciphertext using old key
    plaintext = old_fernet.decrypt(old_ciphertext)
    # 2. Generate new key
    new_key = Fernet.generate_key()
    # 3. Encrypt data using new key
    new_ciphertext = new_fernet.encrypt(plaintext)
    # 4. Save new ciphertext
    write_to_file("data/encrypted_data.txt", new_ciphertext)
    # 5. Mark old key as REVOKED and activate new key
    revoked_keys.append(old_key)
    active_key = new_key
```

---

## 9. Security Analysis
1. **Confidentiality**: Protected by Fernet (AES-128 in CBC mode with PKCS7 padding and HMAC-SHA256 authentication).
2. **Key Rotation Benefit**: Limits cryptanalysis exposure window. Even if a historical key leaks, newly encrypted data remains secure under $K_{new}$.
3. **Unauthorized Access Protection**: Decryption with any key other than the designated key immediately aborts due to cryptographic MAC verification failure.
4. **Key Revocation**: Old keys are invalidated and never reused.
5. **Cryptographic Erasure (Deletion)**: Purging the key from memory and disk renders existing ciphertext unrecoverable without needing to overwrite gigabytes of raw data.

---

## 10. Testing Plan
- **Test 1**: Key Generation produces active key and key ID.
- **Test 2**: Encryption generates valid base64 ciphertext and stores it.
- **Test 3**: Decryption with correct key returns original plaintext.
- **Test 4**: Decryption with wrong key triggers "Access denied - incorrect key".
- **Test 5**: Waiting 60 seconds triggers automatic rotation.
- **Test 6**: Decryption with new key successfully recovers data.
- **Test 7**: Old key is marked REVOKED in history.
- **Test 8**: Deletion of key permanently invalidates decryption.

---

## 11. Demonstration Plan (3–5 Minute Presentation)
1. **Start Dashboard**: Show `http://127.0.0.1:5000` with clean UI.
2. **Generate Key**: Click `[ Generate Key ]`, show Key ID and status `ACTIVE`.
3. **Encrypt Data**: Enter `"Patient ID: 101, Model Result: Low Risk"`, click `[ Encrypt Data ]`, observe unreadable ciphertext token.
4. **Decrypt Data**: Click `[ Decrypt Data ]`, verify correct recovery.
5. **Security Test**: Click `[ Test Unauthorized Access ]`, observe instant rejection (`Access denied - incorrect key`).
6. **Demonstrate Rotation**: Click `[ Rotate Key (Force Demo) ]` or wait 60s, observe rotation counter increment, old key marked `REVOKED`, new key marked `ACTIVE`.
7. **Verify Continuity**: Click `[ Decrypt Data ]` to show data re-encrypted seamlessly.
8. **Cryptographic Erasure**: Click `[ Delete Key ]`, then attempt decrypt to show access denial.

---

## 12. Expected Results
- All actions execute in $< 50$ milliseconds.
- Data integrity is preserved across key rotations.
- Unauthorized keys are 100% blocked by HMAC authentication.
- Activity log provides complete chronological audit trail.

---

## 13. Cryptographic Standards & Design Specifications

| Domain | Specification | Engineering Rationale |
|---|---|---|
| **Symmetric Primitive** | Fernet (AES-128-CBC + HMAC-SHA256) | Chosen for low latency and high computational efficiency across continuous AI inference pipelines. |
| **Authenticated Encryption** | Dual-key Fernet construction | Combines confidentiality with cryptographic authentication to immediately detect forged tokens. |
| **Cryptoperiod Strategy** | Automated time-triggered re-keying | Mitigates long-term key compromise risks by strictly limiting the operational cryptoperiod. |
| **Zero-Loss Re-encryption** | Sequential decrypt-encrypt atomic pipeline | Decrypts with retiring active key, generates fresh 256-bit key, and re-encrypts before marking old key revoked. |
| **Sanitization Model** | Cryptographic Erasure | Deterministic key destruction rendering ciphertext permanently unrecoverable. |
