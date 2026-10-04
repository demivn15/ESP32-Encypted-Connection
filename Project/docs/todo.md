**Objective:** design and implement a wireless communication system that allows at least two IoT devices to exchange short text messages securely.

The system must include:

- Confidentiality, integrity, device authentication, and protection against replay attacks;
- A valid message must only be accepted after the receiver has verified both its origin and its integrity;

> Key characteristics of the system: confidentiality + Integrity + Authentication + Replay Protection.

## Process description

- Session key establishment: Diffie–Hellman.
- All text messages must be encrypted before transmission: AES-GCM or ChaCha20-Poly1305.
- The receiving device must reject any message whose ciphertext, authentication information, sender information, or freshness data has been altered.
- The implementation must also include a mechanism to detect repeated messages: sequence numbers, counters, timestamps, nonces, or session identifiers may be used for this purpose.

## Technical report

The technical report must include a basic performance evaluation of the implemented system:

- Record the plaintext message size;
- the final protected packet size;
- the encryption time;
- the decryption and verification time;
- and the communication latency;

> Discuss the computational and communication overhead introduced by the cryptographic protection.

*Deliverables: Complete source code, a system architecture diagram, a protocol sequence diagram, the specification of the transmitted message format, and a short technical report describing the cryptographic design and the experimental results*
