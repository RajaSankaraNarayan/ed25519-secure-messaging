# Ed25519 Secure Messaging & Active MITM Attack Simulator

An interactive cryptographic messaging prototype and offensive security testbed built in **Python 3.10+** using `cryptography` and `rich`.

This project implements an authenticated messaging protocol between participants (`Alice` and `Bob`) over an untrusted network controlled by an active Dolev-Yao adversary (`Mallory`). It demonstrates how **Ed25519 (RFC 8032)** digital signatures enforce **message integrity**, **sender authenticity**, and **non-repudiation**, while exposing—and defending against—protocol-level vulnerabilities including **in-transit tampering**, **key-directory poisoning (Public-Key Substitution)**, **cleartext metadata/payload exposure**, and **packet replay attacks**.

---

## 1. Core Cryptographic Architecture

The protocol layers asymmetric digital signatures, authenticated symmetric encryption, out-of-band key pinning, and stateful replay tracking into a deterministic verification pipeline:

* **Digital Signatures (`Ed25519` / RFC 8032):** Provides 128-bit security ($\approx$ 3072-bit RSA) with compact 32-byte public keys and 64-byte signatures. Uses deterministic SHA-512 nonce derivation to eliminate random-number-generator ($k$-reuse) vulnerabilities and branchless Twisted Edwards curve arithmetic for side-channel resistance.
* **Confidentiality Extension (`AES-256-GCM` Encrypt-then-Sign):** Because digital signatures do not hide message contents, the protocol includes an optional **Encrypt-then-Sign (EtS)** layer using 256-bit AES in Galois/Counter Mode with a 96-bit CSPRNG nonce (`os.urandom(12)`). The outer Ed25519 signature covers both the Base64 ciphertext and the GCM nonce, preventing attackers from feeding unauthenticated ciphertexts into the decryption routine.
* **Out-of-Band Key Authentication (`SHA-256` Fingerprints):** Simulates a public-key registry alongside a pinned out-of-band fingerprint store (`SHA-256` digest of the raw 32-byte Ed25519 public key) to detect Public-Key Substitution (MITM key-swapping) attacks.
* **Stateful Replay Protection:** Combines monotonically increasing per-sender sequence counters (`counter`), 128-bit UUIDv4 message IDs (`msg_id`), and bounded UTC timestamps (`max_age_seconds = 300`) inside the signed envelope to prevent packet capture-and-replay attacks.

---

## 2. Wire Packet Format & Canonical Serialization

Every transmitted message is encapsulated as a JSON packet containing a signed `"envelope"` and a Base64-encoded 64-byte `"signature"`:

```json
{
  "envelope": {
    "counter": 1,
    "encrypted": false,
    "msg_id": "a4f9d210-7c4e-4b89-9d1a-88c3e5f01234",
    "nonce": null,
    "payload": "Transfer $500 to project escrow account #8821.",
    "recipient": "Bob",
    "sender": "Alice",
    "timestamp": 1730000000
  },
  "signature": "base64-encoded-64-byte-ed25519-signature"
}