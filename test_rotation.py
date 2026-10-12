"""
test_rotation.py - Verification of the 8 Required Test Cases
"""

import time
import os
import key_manager

def run_all_tests():
    print("=" * 60)
    print("RUNNING 8 TEST CASES FOR KEY MANAGEMENT MICRO PROJECT")
    print("=" * 60)

    # Clean previous data if any
    if os.path.exists(key_manager.KEY_FILE):
        os.remove(key_manager.KEY_FILE)
    if os.path.exists(key_manager.DATA_FILE):
        os.remove(key_manager.DATA_FILE)

    # Test 1: Generate key -> SUCCESS
    t1 = key_manager.generate_key()
    assert t1["success"] is True, "Test 1 Failed"
    key_id_1 = t1["key_id"]
    print(f"[PASS] Test 1: Generate key -> SUCCESS ({key_id_1})")

    # Test 2: Encrypt data -> SUCCESS
    sample_data = "Patient ID: 101, Model Result: Low Risk"
    t2 = key_manager.encrypt_data(sample_data)
    assert t2["success"] is True, "Test 2 Failed"
    assert "ciphertext" in t2, "Test 2 Missing Ciphertext"
    print(f"[PASS] Test 2: Encrypt data -> SUCCESS (Ciphertext length: {len(t2['ciphertext'])})")

    # Test 3: Decrypt using correct key -> SUCCESS
    t3 = key_manager.decrypt_data()
    assert t3["success"] is True, "Test 3 Failed"
    assert t3["decrypted_data"] == sample_data, "Test 3 Data Mismatch"
    print(f"[PASS] Test 3: Decrypt using correct key -> SUCCESS ('{t3['decrypted_data']}')")

    # Test 4: Decrypt using wrong key -> FAIL / ACCESS DENIED
    t4 = key_manager.test_unauthorized_access()
    assert t4["success"] is False, "Test 4 Expected Failure"
    assert "Access denied" in t4["message"], "Test 4 Unexpected Message"
    print(f"[PASS] Test 4: Decrypt using wrong key -> FAIL / ACCESS DENIED ('{t4['message']}')")

    # Test 5: Automatic key rotation (simulate time >= lifetime)
    store = key_manager.load_key_store()
    # artificially set created_at to 65 seconds ago
    store["active_key"]["created_at"] = time.time() - 65
    key_manager.save_key_store(store)
    
    rotated = key_manager.check_key_expiry()
    assert rotated is True, "Test 5 Key Expiry Did Not Trigger Rotation"
    print("[PASS] Test 5: Key expiry condition reached -> automatic key rotation triggered")

    # Test 6: Decrypt re-encrypted data using new key -> SUCCESS
    store_after = key_manager.load_key_store()
    key_id_2 = store_after["active_key"]["key_id"]
    assert key_id_1 != key_id_2, "Test 6 Key ID did not change"
    t6 = key_manager.decrypt_data()
    assert t6["success"] is True, "Test 6 Decryption with new key failed"
    assert t6["decrypted_data"] == sample_data, "Test 6 Data mismatch after rotation"
    print(f"[PASS] Test 6: Decrypt re-encrypted data using new key -> SUCCESS ({key_id_1} -> {key_id_2})")

    # Test 7: Old key should be marked revoked
    revoked_list = store_after["revoked_keys"]
    assert any(k["key_id"] == key_id_1 for k in revoked_list), "Test 7 Old key not in revoked list"
    assert revoked_list[0]["status"] == "REVOKED", "Test 7 Status not REVOKED"
    print(f"[PASS] Test 7: Old key marked revoked -> SUCCESS ({key_id_1} status: REVOKED)")

    # Test 8: Delete key -> data becomes inaccessible
    t8 = key_manager.delete_key()
    assert t8["success"] is True, "Test 8 Delete key failed"
    t8_decrypt = key_manager.decrypt_data()
    assert t8_decrypt["success"] is False, "Test 8 Data was still decryptable!"
    print(f"[PASS] Test 8: Delete key -> data becomes inaccessible ('{t8_decrypt['message']}')")

    print("=" * 60)
    print("ALL 8 TEST CASES PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()
