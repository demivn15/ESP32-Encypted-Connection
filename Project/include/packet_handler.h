#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stddef.h>
#include <stdint.h>
#include <Arduino.h>

constexpr size_t kMaxPayloadLength = 128;

// Enum to distinguish packet types over the air
enum class PacketType : uint8_t {
    kHandshake = 0x01,
    kData = 0x02
};

struct SecurePacket {
    // Format: Type (1) || ID_S (6) || SID (4) || SEQ (4) || Nonce (12) || Payload_Len (2) || Payload (L) || TAG (16)
    PacketType type;                      // Packet type flag (Handshake vs Data)
    uint8_t senderId[6];                  // ID_S: MAC address of sender
    uint32_t sessionId;                   // SID: Established session identifier
    uint32_t sequenceNumber;              // SEQ: Monotonic counter for replay protection
    uint8_t nonce[12];                    // N: AES-GCM Unique Nonce/IV
    uint16_t payloadLength;               // Length of payload (ciphertext or public key)
    uint8_t payload[kMaxPayloadLength];   // Payload content (encrypted text or raw public key)
    uint8_t tag[16];                      // TAG: AES-GCM Authentication Tag (0s if handshake)
};

class PacketHandler {
public:
    static size_t Serialize(const SecurePacket& packet, uint8_t* destinationBuffer, size_t maxLength);
    static bool Deserialize(const uint8_t* sourceBuffer, size_t length, SecurePacket& packet);
};

#endif  // PACKET_HANDLER_H