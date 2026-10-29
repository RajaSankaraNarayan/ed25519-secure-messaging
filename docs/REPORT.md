---

### Deliverable 3: Complete Technical Report (`REPORT.md`)[cite: 1]

```markdown
# Technical Security Report — Project 2: Secure Messaging With Digital Signatures

---

## 1. System Design & Architecture

### 1.1 Cryptographic Library & Primitive Selection
The system is built on Python's industry-standard `cryptography` library (`cryptography.hazmat.primitives`), which provides bindings to audited, constant-time C/Rust implementations (OpenSSL) rather than error-prone custom arithmetic.

#### Why Ed25519 (RFC 8032)?
We selected **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519 using SHA-512) over legacy RSA-PSS or NIST P-256 ECDSA for four security and engineering reasons:
1. **128-Bit Security Level with Compact Keys:** Ed25519 provides $\approx 2^{128}$ security against Pollard's rho algorithm for discrete logarithms, matching 3072-bit RSA while requiring only **32-byte public keys** and **64-byte signatures**.
2. **Deterministic Nonce Generation (Eliminating $k$-Reuse Vulnerabilities):** Standard ECDSA requires a fresh random per-message nonce $k$. If the random number generator fails and reuses $k$ across two different messages $m_1, m_2$ (as occurred in the 2010 Sony PlayStation 3 firmware signing breach), an attacker can algebraically recover the private key $d_A$. Ed25519 derives the per-message scalar $r$ deterministically by hashing a secret prefix and the message itself using SHA-512:
   $$r = \text{SHA-512}(\text{prefix} \parallel M) \pmod{\ell}$$
   where $\ell = 2^{252} + 27742317777372353535851937790883648493$ is the prime order of the base point $B$.
3. **Side-Channel Timing Resistance:** Twisted Edwards curves use complete addition formulas that execute identical field operations regardless of whether points are distinct or doubled. Combined with branchless scalar multiplication, Ed25519 prevents timing side-channel leaks of private key bits.
4. **Fast Batch & Single Verification:** Verification requires computing $[S]B = R + [k]A$, which executes in under 100 microseconds on modern CPUs without requiring modular inversion during verification.

---

### 1.2 Protocol Architecture & Mermaid Sequence Diagrams

#### Diagram 1: Normal Signing, Verification, and Optional AES-256-GCM Encrypt-then-Sign Flow
```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice (Sender)
    participant Dir as PublicKeyDirectory
    participant Wire as Network Wire (Untrusted)
    participant Bob as Bob (Recipient)

    Note over Alice,Bob: Setup Phase: Key Registration & Out-of-Band Fingerprint Pinning
    Alice->>Dir: register_user("Alice", PK_Alice, update_trusted_fingerprint=True)
    Bob->>Dir: register_user("Bob", PK_Bob, update_trusted_fingerprint=True)

    Note over Alice: 1. Counter Increment & Optional AEAD Encryption
    Alice->>Alice: counter += 1, timestamp = UTC_NOW(), msg_id = UUIDv4()
    opt Optional Confidentiality Extension (shared_aes_key provided)
        Alice->>Alice: nonce = os.urandom(12)
        Alice->>Alice: ciphertext = AES-256-GCM.Encrypt(shared_aes_key, nonce, plaintext, AAD=None)
        Alice->>Alice: payload = Base64(ciphertext), encrypted = True
    end

    Note over Alice: 2. Canonical Serialization & Ed25519 Signing (Encrypt-then-Sign)
    Alice->>Alice: canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(',',':'))
    Alice->>Alice: signature = Ed25519.Sign(SK_Alice, canonical_bytes)
    Alice->>Wire: Transmit JSON Packet {"envelope": envelope, "signature": Base64(signature)}

    Wire->>Bob: Deliver JSON Packet
    Note over Bob: 3. Verification Order of Operations
    Bob->>Dir: get_public_key("Alice", verify_fingerprint=True)
    Dir-->>Bob: Return PK_Alice (Verified against SHA-256(PK_Alice) == trusted_fingerprint)
    Bob->>Bob: Reconstruct canonical_bytes from packet["envelope"]
    Bob->>Bob: Ed25519.Verify(PK_Alice, canonical_bytes, signature)
    Bob->>Bob: Verify Replay State: (sender, counter) not in seen_messages & counter > last_counter & |now - timestamp| <= 300s
    opt If envelope["encrypted"] == True
        Bob->>Bob: plaintext = AES-256-GCM.Decrypt(shared_aes_key, nonce, ciphertext, AAD=None)
    end
    Bob-->>Bob: Return {"valid": True, "status_code": "SUCCESS", "plaintext": plaintext}

    sequenceDiagram
    autonumber
    participant Mallory as Mallory (MITM Attacker)
    participant Dir as PublicKeyDirectory
    participant Bob as Bob (Recipient)

    Note over Mallory,Dir: Attack Setup: Mallory compromises the central directory
    Mallory->>Dir: tamper_registry_key("Alice", PK_Mallory)
    Note right of Dir: registry["Alice"] = PK_Mallory<br/>trusted_fingerprints["Alice"] remains SHA-256(PK_Alice)

    Mallory->>Mallory: Craft envelope with "sender": "Alice", sign with SK_Mallory
    Mallory->>Bob: Send forged_packet

    rect rgb(80, 20, 20)
        Note over Bob,Dir: Part A: Vulnerable Mode (verify_key_fingerprint=False)
        Bob->>Dir: get_public_key("Alice", verify_fingerprint=False)
        Dir-->>Bob: Returns PK_Mallory (Unauthenticated!)
        Bob->>Bob: Ed25519.Verify(PK_Mallory, envelope, sig_Mallory) -> PASSES!
        Bob-->>Bob: valid=True, status_code="SUCCESS" (CRITICAL VULNERABILITY)
    end

    rect rgb(20, 65, 35)
        Note over Bob,Dir: Part B: Defended Mode (verify_key_fingerprint=True)
        Bob->>Dir: get_public_key("Alice", verify_fingerprint=True)
        Dir->>Dir: Compare SHA-256(PK_Mallory) != trusted_fingerprints["Alice"]
        Dir-->>Bob: Raises SecurityError("PUBLIC KEY SUBSTITUTION DETECTED")
        Bob-->>Bob: valid=False, status_code="KEY_SUBSTITUTION_DETECTED" (ATTACK BLOCKED)
    end


    sequenceDiagram
    autonumber
    participant Alice as Alice (Sender)
    participant Mallory as Mallory (Eavesdropper / Replayer)
    participant Bob as Bob (Recipient)

    Alice->>Bob: Send Valid Packet P1 (counter=1, timestamp=T0, payload="Pay $50 to contractor")
    Note over Mallory: Passively records exact JSON Packet P1 off the wire
    Bob->>Bob: Verify Signature + Check (Alice, 1) not seen -> Record last_counter["Alice"] = 1
    Bob-->>Bob: Accept P1 (status_code="SUCCESS")

    Note over Mallory,Bob: Attack Phase: Mallory replays recorded Packet P1
    Mallory->>Bob: Retransmit identical Packet P1 (counter=1)

    rect rgb(80, 20, 20)
        Note over Bob: Part A: Replay Defense OFF (enforce_replay_defense=False)
        Bob->>Bob: Ed25519.Verify(PK_Alice, P1) -> Mathematically Valid!
        Bob-->>Bob: valid=True, status_code="SUCCESS" (Duplicate $50 payment executed!)
    end

    rect rgb(20, 65, 35)
        Note over Bob: Part B: Replay Defense ON (enforce_replay_defense=True)
        Bob->>Bob: Ed25519.Verify(PK_Alice, P1) -> Valid
        Bob->>Bob: Check counter=1 <= last_counter["Alice"] (1) OR ("Alice", 1) in seen_messages
        Bob-->>Bob: valid=False, status_code="REPLAY_DETECTED" (Duplicate rejected!)
    end

    rect rgb(20, 65, 35)
        Note over Mallory,Bob: Part C: Mallory increments P1["envelope"]["counter"] = 2 without SK_Alice
        Mallory->>Bob: Send modified P1' (counter=2, original signature for counter=1)
        Bob->>Bob: Ed25519.Verify(PK_Alice, canonical_bytes(counter=2), sig(counter=1))
        Bob-->>Bob: valid=False, status_code="INVALID_SIGNATURE" (Tampering blocked!)
    end

    