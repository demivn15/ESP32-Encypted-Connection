#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stddef.h>
#include <stdint.h>

#include <Arduino.h>

constexpr size_t kMaxPayloadLength = 128;

// Define the structure for packet formating:
// ID_S (6) || SID (4) || SEQ (4) || Nonce (12) || Payload_Len (2) || Ciphertext (C) || TAG (16)
struct SecurePacket {
    uint8_t senderId[6];
    uint32_t sessionId;
    uint32_t sequenceNumber;
    uint8_t nonce[12];
    uint16_t ciphertextLength;
    uint8_t ciphertext[kMaxPayloadLength];
    uint8_t tag[16];
};

class PacketHandler {
public:
    // Serializes the SecurePacket struct into a raw byte array for wireless transmission.
    static size_t Serialize(const SecurePacket& packet, uint8_t* destinationBuffer, size_t maxLength);
    // Deserializes a raw byte array back into the SecurePacket struct upon reception.
    static bool Deserialize(const uint8_t* sourceBuffer, size_t length, SecurePacket& packet);
};

#endif