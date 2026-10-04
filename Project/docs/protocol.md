<!-- Mermaid code for the Protocol Protocol Sequence diagram -->

---
config:
  theme: neutral
---
sequenceDiagram
    Sender->>+Receiver: ECDH Public Key Exchange
    Receiver->>+Sender: ECDH Public Key Exchange
    note over Sender,Receiver: Derive Shared Session Key (Ks) via HKDF
    note left of Sender: Encrypt Plaintext (AES-GCM, SEQ++, Nonce)
    note left of Sender: Construct Packet: [ID || SID || SEQ || N || C || TAG]
    Sender ->>+Receiver: Transmit Wireless Packet
    note right of Receiver: Verify Sender and SID
    note right of Receiver: Check SEQ (Replay Protection)
    note right of Receiver: Decrypt & Verify TAG (AES-GCM)
    note right of Receiver: Extract Plaintext Message