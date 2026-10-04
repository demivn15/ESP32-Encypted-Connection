#include "packet_handler.h"
#include <string.h>

size_t PacketHandler::Serialize(const SecurePacket& packet, uint8_t* destinationBuffer, size_t maxLength) {
    // Type(1) + ID_S(6) + SID(4) + SEQ(4) + Nonce(12) + Payload_Len(2) + Payload(L) + TAG(16)
    size_t requiredLength = 1 + 6 + 4 + 4 + 12 + 2 + packet.payloadLength + 16;

    if (destinationBuffer == nullptr || maxLength < requiredLength) {
        return 0;
    }

    size_t offset = 0;

    // 1. Copy Packet Type (1 byte)
    destinationBuffer[offset] = static_cast<uint8_t>(packet.type);
    offset += 1;

    // 2. Copy Sender ID (6 bytes)
    memcpy(destinationBuffer + offset, packet.senderId, 6);
    offset += 6;

    // 3. Copy Session ID (4 bytes)
    memcpy(destinationBuffer + offset, &packet.sessionId, 4);
    offset += 4;

    // 4. Copy Sequence Number (4 bytes)
    memcpy(destinationBuffer + offset, &packet.sequenceNumber, 4);
    offset += 4;

    // 5. Copy Nonce (12 bytes)
    memcpy(destinationBuffer + offset, packet.nonce, 12);
    offset += 12;

    // 6. Copy Payload Length (2 bytes)
    memcpy(destinationBuffer + offset, &packet.payloadLength, 2);
    offset += 2;

    // 7. Copy Payload (variable L bytes)
    if (packet.payloadLength > kMaxPayloadLength) {
        return 0;
    }
    memcpy(destinationBuffer + offset, packet.payload, packet.payloadLength);
    offset += packet.payloadLength;

    // 8. Copy Authentication Tag (16 bytes)
    memcpy(destinationBuffer + offset, packet.tag, 16);
    offset += 16;

    return offset;
}

bool PacketHandler::Deserialize(const uint8_t* sourceBuffer, size_t length, SecurePacket& packet) {
    const size_t kMinHeaderTagLength = 1 + 6 + 4 + 4 + 12 + 2 + 16;

    if (sourceBuffer == nullptr || length < kMinHeaderTagLength) {
        return false;
    }

    size_t offset = 0;

    // 1. Extract Packet Type (1 byte)
    packet.type = static_cast<PacketType>(sourceBuffer[offset]);
    offset += 1;

    // 2. Extract Sender ID (6 bytes)
    memcpy(packet.senderId, sourceBuffer + offset, 6);
    offset += 6;

    // 3. Extract Session ID (4 bytes)
    memcpy(&packet.sessionId, sourceBuffer + offset, 4);
    offset += 4;

    // 4. Extract Sequence Number (4 bytes)
    memcpy(&packet.sequenceNumber, sourceBuffer + offset, 4);
    offset += 4;

    // 5. Extract Nonce (12 bytes)
    memcpy(packet.nonce, sourceBuffer + offset, 12);
    offset += 12;

    // 6. Extract Payload Length (2 bytes)
    memcpy(&packet.payloadLength, sourceBuffer + offset, 2);
    offset += 2;

    // Validate payload length bounds
    if (packet.payloadLength > kMaxPayloadLength || length < (offset + packet.payloadLength + 16)) {
        return false;
    }

    // 7. Extract Payload (L bytes)
    memcpy(packet.payload, sourceBuffer + offset, packet.payloadLength);
    offset += packet.payloadLength;

    // 8. Extract Authentication Tag (16 bytes)
    memcpy(packet.tag, sourceBuffer + offset, 16);
    offset += 16;

    return true;
}