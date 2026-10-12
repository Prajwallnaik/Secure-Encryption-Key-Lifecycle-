"""
key_manager.py - Core Key Lifecycle and Cryptographic Management Engine
College DSP Micro Project:
"Secure Key Management for AI/ML Applications with Automatic Key Rotation"

Lifecycle stages demonstrated:
Generation -> Storage -> Usage (Encrypt/Decrypt) -> Rotation -> Revocation -> Deletion
"""

import os
import json
import time
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet, InvalidToken

# Data directory and file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_FILE = os.path.join(DATA_DIR, "key.json")
DATA_FILE = os.path.join(DATA_DIR, "encrypted_data.txt")

# Default rotation lifetime: 60 seconds (for college presentation)
DEFAULT_KEY_LIFETIME = 60

# In-memory activity log
activity_log = []


def log_activity(message: str):
    """Record an action with a timestamp in the activity log."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    entry = f"[{timestamp}] {message}"
    activity_log.append(entry)
    # Keep the log to a reasonable size
    if len(activity_log) > 50:
        activity_log.pop(0)


def _ensure_data_dir():
    """Ensure data/ folder exists."""
    os.makedirs(DATA_DIR, exist_ok=True)


def _hash_key_id(key_bytes: bytes) -> str:
    """Generate a clean, readable Key ID fingerprint (e.g., KEY-A1B2C3D4)."""
    digest = hashlib.sha256(key_bytes).hexdigest()[:8].upper()
    return f"KEY-{digest}"


def load_key_store() -> dict:
    """Load key store dictionary from data/key.json."""
    _ensure_data_dir()
    if not os.path.exists(KEY_FILE):
        return {
            "active_key": None,
            "revoked_keys": [],
            "rotation_count": 0,
            "key_lifetime": DEFAULT_KEY_LIFETIME,
        }
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "active_key": None,
            "revoked_keys": [],
            "rotation_count": 0,
            "key_lifetime": DEFAULT_KEY_LIFETIME,
        }


def save_key_store(store: dict):
    """Save key store dictionary to data/key.json."""
    _ensure_data_dir()
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=4)


def generate_key() -> dict:
    """
    1. KEY GENERATION
    Generates a secure random 256-bit Fernet symmetric key.
    Stores metadata and key string in data/key.json.
    Does NOT expose raw secret key bytes to the dashboard.
    """
    raw_key = Fernet.generate_key()  # URL-safe base64-encoded 32-byte key
    key_id = _hash_key_id(raw_key)
    now = time.time()
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    store = load_key_store()

    # If there was an existing active key, revoke it
    if store.get("active_key"):
        old_key = store["active_key"]
        store["revoked_keys"].insert(0, {
            "key_id": old_key["key_id"],
            "revoked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "REVOKED"
        })

    store["active_key"] = {
        "key_id": key_id,
        "key_bytes": raw_key.decode("utf-8"),
        "created_at": now,
        "created_time_str": time_str,
        "status": "ACTIVE",
    }

    store["is_deleted"] = False
    save_key_store(store)
    log_activity(f"Key generated successfully ({key_id})")

    return {
        "success": True,
        "message": "Key generated successfully",
        "key_id": key_id,
        "created_time": time_str,
        "status": "ACTIVE",
    }


def encrypt_data(plaintext: str) -> dict:
    """
    2. ENCRYPTION
    Encrypts sensitive AI/ML text using the active Fernet key.
    Saves ciphertext to data/encrypted_data.txt.
    Does NOT store the original plaintext.
    """
    if not plaintext or not plaintext.strip():
        return {"success": False, "message": "Plaintext data cannot be empty."}

    store = load_key_store()
    active_key_data = store.get("active_key")

    if not active_key_data:
        return {
            "success": False,
            "message": "Encryption failed: No active key available. Please generate a key first.",
        }

    key_bytes = active_key_data["key_bytes"].encode("utf-8")
    fernet = Fernet(key_bytes)

    # Perform symmetric encryption: C = E(K, D)
    ciphertext_bytes = fernet.encrypt(plaintext.encode("utf-8"))
    ciphertext_str = ciphertext_bytes.decode("utf-8")

    # Store ciphertext to file
    _ensure_data_dir()
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        f.write(ciphertext_str)

    log_activity(f"Data encrypted successfully using {active_key_data['key_id']}")

    return {
        "success": True,
        "message": "Data encrypted successfully",
        "ciphertext": ciphertext_str,
        "key_id": active_key_data["key_id"],
    }


def decrypt_data(key_override: bytes = None) -> dict:
    """
    3. DECRYPTION
    Reads ciphertext from data/encrypted_data.txt.
    Decrypts using the active key (or key_override for security tests).
    """
    if not os.path.exists(DATA_FILE):
        return {"success": False, "message": "Decryption failed: No encrypted data found."}

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        ciphertext_str = f.read().strip()

    if not ciphertext_str:
        return {"success": False, "message": "Decryption failed: Encrypted data file is empty."}

    # Determine which key to use
    if key_override is not None:
        key_bytes = key_override
    else:
        store = load_key_store()
        active_key_data = store.get("active_key")
        if not active_key_data:
            return {
                "success": False,
                "message": "Decryption failed: Unauthorized or invalid key (No active key found).",
            }
        key_bytes = active_key_data["key_bytes"].encode("utf-8")

    try:
        fernet = Fernet(key_bytes)
        decrypted_bytes = fernet.decrypt(ciphertext_str.encode("utf-8"))
        decrypted_text = decrypted_bytes.decode("utf-8")

        if key_override is None:
            log_activity("Data decrypted successfully")

        return {
            "success": True,
            "message": "Data decrypted successfully",
            "decrypted_data": decrypted_text,
        }
    except (InvalidToken, Exception):
        return {
            "success": False,
            "message": "Decryption failed: Unauthorized or invalid key",
        }


def rotate_key(automatic: bool = False) -> dict:
    """
    4. AUTOMATIC / MANUAL KEY ROTATION
    Rotates the active key:
      OLD KEY
         ↓
      Decrypt existing encrypted data
         ↓
      Generate NEW KEY
         ↓
      Encrypt data using NEW KEY
         ↓
      Store NEW KEY
         ↓
      Invalidate / Revoke OLD KEY
    Updates the rotation counter.
    """
    store = load_key_store()
    old_key_data = store.get("active_key")

    if not old_key_data:
        return {
            "success": False,
            "message": "Cannot rotate: No active key exists. Please generate a key first.",
        }

    old_key_id = old_key_data["key_id"]
    old_key_bytes = old_key_data["key_bytes"].encode("utf-8")

    # Step 1: Decrypt existing data using OLD KEY if encrypted data exists
    existing_plaintext = None
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            cipher_content = f.read().strip()
        if cipher_content:
            try:
                old_fernet = Fernet(old_key_bytes)
                existing_plaintext = old_fernet.decrypt(cipher_content.encode("utf-8")).decode("utf-8")
            except Exception as e:
                # If existing data could not be decrypted, do not silently lose it
                return {
                    "success": False,
                    "message": f"Rotation aborted: Failed to decrypt existing data with old key ({e})",
                }

    # Step 2: Generate NEW KEY
    new_raw_key = Fernet.generate_key()
    new_key_id = _hash_key_id(new_raw_key)
    now = time.time()
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Step 3: Re-encrypt existing data with NEW KEY
    if existing_plaintext is not None:
        new_fernet = Fernet(new_raw_key)
        new_cipher_bytes = new_fernet.encrypt(existing_plaintext.encode("utf-8"))
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            f.write(new_cipher_bytes.decode("utf-8"))

    # Step 4: Revoke OLD KEY
    store["revoked_keys"].insert(0, {
        "key_id": old_key_id,
        "revoked_at": time_str,
        "status": "REVOKED",
    })

    # Step 5: Store NEW KEY
    store["active_key"] = {
        "key_id": new_key_id,
        "key_bytes": new_raw_key.decode("utf-8"),
        "created_at": now,
        "created_time_str": time_str,
        "status": "ACTIVE",
    }
    store["rotation_count"] = store.get("rotation_count", 0) + 1
    save_key_store(store)

    # Step 6: Log activity
    prefix = "Automatic" if automatic else "Manual (Demo)"
    log_activity(f"{prefix} key rotation completed: {old_key_id} -> {new_key_id}")
    log_activity(f"Old key revoked ({old_key_id})")

    return {
        "success": True,
        "message": f"{prefix} key rotation completed",
        "old_key_id": old_key_id,
        "new_key_id": new_key_id,
        "rotation_count": store["rotation_count"],
    }


def check_key_expiry() -> bool:
    """
    5. EXPIRY CHECK FOR AUTOMATIC TIME-BASED KEY ROTATION
    Checks if:
      current_time - key_creation_time >= KEY_LIFETIME
    If expired, triggers automatic key rotation.
    """
    store = load_key_store()
    active_key = store.get("active_key")
    if not active_key:
        return False

    lifetime = store.get("key_lifetime", DEFAULT_KEY_LIFETIME)
    age = time.time() - active_key.get("created_at", 0)

    if age >= lifetime:
        rotate_key(automatic=True)
        return True
    return False


def delete_key() -> dict:
    """
    6. KEY DELETION / CRYPTOGRAPHIC ERASURE
    Deletes the current active key.
    Encrypted data remains stored but becomes permanently inaccessible.
    """
    store = load_key_store()
    active_key = store.get("active_key")

    if not active_key:
        return {"success": False, "message": "No active key to delete."}

    deleted_id = active_key["key_id"]
    store["active_key"] = None
    store["is_deleted"] = True
    save_key_store(store)

    log_activity(f"Key deleted successfully ({deleted_id}). Encrypted data is now inaccessible.")

    return {
        "success": True,
        "message": "Key deleted successfully",
        "deleted_key_id": deleted_id,
    }


def test_unauthorized_access() -> dict:
    """
    7. SECURITY TEST: WRONG KEY INTRUSION ATTEMPT
    Generates a temporary wrong key and attempts to decrypt the encrypted data.
    Expected outcome: Access denied — incorrect key
    """
    if not os.path.exists(DATA_FILE):
        return {
            "success": False,
            "message": "No encrypted data exists to test. Please encrypt sample data first.",
        }

    # Generate a distinct random wrong Fernet key
    wrong_key = Fernet.generate_key()
    wrong_key_id = _hash_key_id(wrong_key)

    result = decrypt_data(key_override=wrong_key)

    log_activity(f"Security Test: Unauthorized decryption attempt using wrong key ({wrong_key_id}) - BLOCKED")

    return {
        "success": False,
        "wrong_key_id": wrong_key_id,
        "message": "Access denied - incorrect key",
    }


def get_dashboard_state() -> dict:
    """
    Gathers all operational metrics required for the dashboard.
    Automatically checks key expiration before returning state.
    """
    check_key_expiry()

    store = load_key_store()
    active_key = store.get("active_key")
    lifetime = store.get("key_lifetime", DEFAULT_KEY_LIFETIME)

    if active_key:
        age_seconds = int(time.time() - active_key.get("created_at", 0))
        remaining_seconds = max(0, lifetime - age_seconds)
        key_status = active_key.get("status", "ACTIVE")
        key_id = active_key.get("key_id", "N/A")
        created_time = active_key.get("created_time_str", "N/A")
    else:
        age_seconds = 0
        remaining_seconds = 0
        key_status = "NO KEY"
        key_id = "None"
        created_time = "N/A"

    # Check ciphertext status
    ciphertext = ""
    encryption_status = "No data encrypted"
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                ciphertext = f.read().strip()
                if ciphertext:
                    encryption_status = f"Encrypted Data Stored ({len(ciphertext)} bytes)"
        except Exception:
            pass

    # Build real-time key lifecycle states
    is_deleted = store.get("is_deleted", False)
    has_active_key = active_key is not None
    has_ciphertext = bool(ciphertext)
    rot_count = store.get("rotation_count", 0)
    revoked_count = len(store.get("revoked_keys", []))

    lifecycle = {
        "generation": {
            "title": "1. Key Generation",
            "status": "ACTIVE" if has_active_key else ("ERASED" if is_deleted else "PENDING"),
            "badge_class": "badge-active" if has_active_key else ("badge-revoked" if is_deleted else "badge-none"),
            "detail": f"{key_id} (256-bit Fernet)" if has_active_key else ("Key Deleted" if is_deleted else "No key generated"),
            "is_active": has_active_key,
        },
        "storage": {
            "title": "2. Key Storage",
            "status": "STORED" if has_active_key else "EMPTY",
            "badge_class": "badge-active" if has_active_key else "badge-none",
            "detail": "Protected in data/key.json" if has_active_key else "No active key saved",
            "is_active": has_active_key,
        },
        "usage": {
            "title": "3. Key Usage",
            "status": "ENCRYPTED" if has_ciphertext else ("READY" if has_active_key else "IDLE"),
            "badge_class": "badge-active" if has_ciphertext else ("badge-none"),
            "detail": "Data protected (C = E(K, D))" if has_ciphertext else "Awaiting encryption",
            "is_active": has_ciphertext,
        },
        "rotation": {
            "title": "4. Key Rotation",
            "status": f"{rot_count} ROTATION(S)" if rot_count > 0 else "MONITORING",
            "badge_class": "badge-active" if rot_count > 0 else "badge-none",
            "detail": f"Auto-timer: {remaining_seconds}s left" if has_active_key else "Rotation idle",
            "is_active": rot_count > 0 or has_active_key,
        },
        "revocation": {
            "title": "5. Key Revocation",
            "status": f"{revoked_count} REVOKED" if revoked_count > 0 else "NONE",
            "badge_class": "badge-revoked" if revoked_count > 0 else "badge-none",
            "detail": f"{revoked_count} old key(s) invalidated" if revoked_count > 0 else "No revoked keys",
            "is_active": revoked_count > 0,
        },
        "deletion": {
            "title": "6. Key Deletion",
            "status": "ERASED" if is_deleted else "INTACT",
            "badge_class": "badge-revoked" if is_deleted else "badge-none",
            "detail": "Cryptographic Erasure" if is_deleted else "Active key retained",
            "is_active": is_deleted,
        },
    }

    return {
        "key_status": key_status,
        "key_id": key_id,
        "created_time": created_time,
        "key_age_seconds": age_seconds,
        "rotation_interval": lifetime,
        "remaining_seconds": remaining_seconds,
        "rotation_count": rot_count,
        "encryption_status": encryption_status,
        "ciphertext": ciphertext,
        "revoked_keys": store.get("revoked_keys", [])[:5],  # top 5 revoked
        "activity_log": list(reversed(activity_log)),  # newest first
        "lifecycle": lifecycle,
    }
