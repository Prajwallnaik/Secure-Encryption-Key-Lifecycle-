# Secure Key Management for AI/ML Applications with Automatic Key Rotation

### *A College DSP (Data Security / Privacy) Micro Project*

---

## 1. Project Title
**Secure Key Management for AI/ML Applications with Automatic Key Rotation**

---

## 2. Problem Statement
In modern machine learning and artificial intelligence workflows, sensitive data—such as patient diagnostic records, biometric face embeddings, credit scoring profiles, and proprietary model weights—must be encrypted at rest and during transit. 

However, many applications rely on static, unmanaged cryptographic keys. If a key is hardcoded or never rotated, a single security breach compromises all historical and future sensitive data. Additionally, encrypting excessive amounts of data with the same key exposes the system to cryptographic cryptanalysis.

---

## 3. Objective
To design, implement, and demonstrate a lightweight, understandable, educational prototype illustrating the complete **Cryptographic Key Lifecycle**:

$$\text{Key Generation} \longrightarrow \text{Key Storage} \longrightarrow \text{Key Usage} \longrightarrow \text{Key Rotation} \longrightarrow \text{Key Revocation} \longrightarrow \text{Key Deletion}$$

The primary innovation over standard key management systems is **Automatic Time-Based Key Rotation** combined with immediate **Re-encryption** so data is never lost.

---

## 4. Existing Problem
In typical basic encryption implementations:
1. **Static Keys**: Keys remain unchanged for months or years.
2. **Infinite Exposure Window**: Compromise of a single key exposes the entire system's history.
3. **No Revocation Mechanism**: Retired keys are not tracked or invalidated.
4. **Data Loss During Key Changes**: Changing keys often breaks backward compatibility or leads to corrupted data.
5. **Lack of Invalidation upon Deletion**: Deleting data usually requires expensive drive overwriting instead of cryptographic erasure.

---

## 5. Proposed Solution
This micro project introduces an automated lifecycle management system:
- **Fernet Symmetric Authenticated Encryption**: AES-128-CBC encryption combined with HMAC-SHA256 authentication.
- **Configurable Lifetime ($\tau = 60\text{ seconds}$)**: The system monitors key age and automatically rotates keys when the lifetime expires.
- **Zero-Data-Loss Rotation**: Existing ciphertext is decrypted with the active key, a fresh high-entropy key is generated, the data is re-encrypted with the new key, and the old key is formally revoked.
- **Simulated Unauthorized Intrusion Detection**: Demonstrates how unauthorized or corrupted keys are rejected.
- **Cryptographic Erasure**: Deleting the key permanently renders the ciphertext inaccessible.

---

## 6. Key Lifecycle

| Stage | Action | System Behavior |
|---|---|---|
| **1. Generation** | `generate_key()` | Generates a 256-bit cryptographically secure Fernet key; assigns a unique Key ID (e.g., `KEY-A1B2C3D4`). |
| **2. Storage** | `save_key_store()` | Stores key metadata in `data/key.json`; never exposes raw key bytes on the main dashboard. |
| **3. Usage** | `encrypt_data()` / `decrypt_data()` | Performs encryption ($C = E(K, D)$) and decryption ($D = E^{-1}(K, C)$). |
| **4. Rotation** | `rotate_key()` | Old key decrypts data $\to$ new key generated $\to$ data re-encrypted $\to$ new key stored. |
| **5. Revocation** | Status: `REVOKED` | Old key is logged as `REVOKED` and excluded from encrypting new payloads. |
| **6. Deletion** | `delete_key()` | Active key is destroyed; existing stored ciphertext cannot be decrypted. |

---

## 7. System Architecture

```
                             +------------------------+
                             |   Web Browser Client   |
                             |  (HTML5 + Vanilla CSS) |
                             +-----------+------------+
                                         | REST / JSON
                                         v
                             +------------------------+
                             |    Flask Controller    |
                             |        (app.py)        |
                             +-----------+------------+
                                         |
                                         v
                             +------------------------+
                             |  Key Lifecycle Engine  |
                             |    (key_manager.py)    |
                             +-----+------------+-----+
                                   |            |
                     Read / Write  |            | Read / Write
                                   v            v
                       +---------------+    +--------------------+
                       | data/key.json |    | encrypted_data.txt |
                       | (Key Storage) |    |    (Ciphertext)    |
                       +---------------+    +--------------------+
```

---

## 8. Mathematical Model

Let:
- $D$ = Sensitive Original Data
- $K$ = Symmetric Secret Key ($K \in \{0, 1\}^{256}$)
- $C$ = Ciphertext ($C \in \{0, 1\}^*$)
- $E(K, D)$ = Fernet Encryption Function
- $E^{-1}(K, C)$ = Fernet Decryption Function
- $T_{created}$ = Key generation timestamp
- $T_{current}$ = Current system timestamp
- $\tau$ = Key lifetime interval ($\tau = 60\text{ seconds}$)

### Encryption:
$$C = E(K, D)$$

### Decryption:
$$D = E^{-1}(K, C)$$

### Key Generation:
$$K = \text{Random}(n) \quad \text{where } n = 256\text{ bits}$$

### Automatic Rotation Condition:
$$\text{If } (T_{current} - T_{created}) \ge \tau \implies K_{old} \longrightarrow K_{new}$$

### Re-encryption Procedure:
$$D = E^{-1}(K_{old}, C) \implies C_{new} = E(K_{new}, D)$$

---

## 9. Implementation
The project is organized into clean, single-responsibility files:

```
secure-key-management/
│
├── app.py              # Flask server and API routing
├── key_manager.py      # Core cryptographic lifecycle functions
├── pyproject.toml      # Modern UV project configuration
├── uv.lock             # Deterministic dependency lockfile
├── README.md           # Complete project documentation
├── brain.md            # In-depth architectural blueprint
│
├── templates/
│   └── index.html      # Responsive dashboard UI
│
├── static/
│   └── style.css       # Clean light-mode stylesheet
│
└── data/
    ├── key.json        # Key metadata and active/revoked key store
    └── encrypted_data.txt # Protected ciphertext storage
```

---

## 10. Automatic Key Rotation
Automatic key rotation addresses the primary drawback of manual key management.

```
       OLD KEY (K_old)
              ↓
  Decrypt existing ciphertext
              ↓
    Generate NEW KEY (K_new)
              ↓
  Encrypt data using NEW KEY
              ↓
     Store NEW KEY (ACTIVE)
              ↓
   Invalidate OLD KEY (REVOKED)
```

The system checks the elapsed key age on every status check:
```python
if current_time - key_creation_time >= KEY_LIFETIME:
    rotate_key(automatic=True)
```
For testing and classroom demonstrations, a **"Force Rotation"** button is also provided to avoid having to wait for 60 seconds.

---

## 11. Security Analysis

1. **Confidentiality**: Protected by Fernet (AES-128-CBC with PKCS7 padding and HMAC-SHA256 signature). Unauthorized parties cannot read plaintext without the key.
2. **Key Rotation**: Limits the cryptographic exposure window. If an older key is leaked, newer data encrypted under $K_{new}$ remains safe.
3. **Unauthorized Access Protection**: Decryption with an incorrect or forged key results in an immediate authentication failure (`Access denied - incorrect key`).
4. **Key Revocation**: Retired keys are stamped `REVOKED` and cannot be used to encrypt new information.
5. **Cryptographic Erasure**: Deleting the key permanently invalidates access to existing ciphertext without requiring physical disk destruction.

---

## 12. Limitation
- **Educational Prototype**: This project is designed specifically for academic demonstration.
- **Local Key Storage**: Keys are stored in `data/key.json` rather than Hardware Security Modules (HSM) or cloud KMS services (e.g., AWS KMS, HashiCorp Vault).
- **Single-Host Concurrency**: Uses local file locks suitable for single-user demonstrations rather than distributed databases.

---

## 13. Future Enhancement
- Integration with Hardware Security Modules (HSMs) or PKCS#11 hardware tokens.
- Integration with enterprise KMS APIs (AWS KMS, Azure Key Vault, Google Cloud KMS).
- Asymmetric envelope encryption (Kms-based Key Encrypting Key + Data Encryption Key).
- Role-based access control (RBAC) with multi-factor authentication (MFA).

---

## 14. How to Run

1. Open a terminal in the project directory:
   ```bash
   cd "secure-key-management"
   ```

2. Sync dependencies and run the application:
   ```bash
   uv run app.py
   ```

3. Open your web browser at:
   ```
   http://127.0.0.1:5000
   ```

4. *(Optional)* Run the cryptographic test suite:
   ```bash
   uv run test_rotation.py
   ```

---

## 15. Expected Output

- **Key Generation**: Status changes to `ACTIVE`, Key ID displays `KEY-XXXXXXXX`, Age resets to `0s`.
- **Encryption**: Ciphertext appears as a secure Fernet token (e.g., `gAAAAABn...`).
- **Decryption**: Plaintext displays `"Patient ID: 101, Model Result: Low Risk"`.
- **Wrong Key Test**: Output displays `Access denied - incorrect key`.
- **Key Rotation**: Old Key is moved to Revoked Keys list, New Key becomes `ACTIVE`, rotation counter increments.
- **Key Deletion**: Status changes to `NO KEY`, subsequent decryption attempts fail.

---

## 16. Cryptographic Specifications & Standards Compliance

| Domain | Specification | Engineering Rationale |
|---|---|---|
| **Cipher Primitive** | AES-128 in CBC mode with PKCS7 padding | Provides robust symmetric confidentiality for high-throughput AI/ML inference records. |
| **Integrity & Authenticity** | HMAC-SHA256 | Guarantees tamper detection and prevents chosen-ciphertext attacks. |
| **Entropy & Key Generation** | `os.urandom(32)` (256-bit key) | Cryptographically secure pseudo-random generation yielding 128-bit encryption + 128-bit MAC keys. |
| **Cryptoperiod Management** | Automated time-based rotation ($\tau = 60\text{s}$) | Limits key exposure window in accordance with NIST SP 800-57 guidelines. |
| **Data Continuity** | Atomic In-Memory Re-encryption | Decrypts ciphertext under $K_{old}$ and re-encrypts under $K_{new}$ before revoking old keys, preventing data corruption. |
| **Data Sanitization** | Cryptographic Erasure | Irrevocably destroys the key to render remaining ciphertext permanently undecipherable. |

