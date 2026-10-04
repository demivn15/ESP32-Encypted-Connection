#include "packet_handler.h"

#include <string.h>

// Calculate total expected packet size based on the specification:
// ID_S (6) + SID (4) + SEQ (4) + Nonce (12) + Payload_Len (2) + Ciphertext (L) + TAG (16)
size_t PacketHandler::Serialize(const SecurePacket& packet, uint8_t* destinationBuffer, size_t maxLength) {
    size_t requiredLength = 44 + packet.ciphertextLength;
    if (destinationBuffer == nullptr || maxLength < requiredLength) { // Buffer is too small or invalid.
        return 0;
    }
    size_t offset = 0;
    memcpy(destinationBuffer + offset, packet.senderId, 6); // 1. Copy Sender ID (6 bytes).
    offset += 6;
    memcpy(destinationBuffer + offset, &packet.sessionId, 4); // 2. Copy Session ID (4 bytes).
    offset += 4;
    memcpy(destinationBuffer + offset, &packet.sequenceNumber, 4); // 3. Copy Sequence Number (4 bytes).
    offset += 4;
    memcpy(destinationBuffer + offset, packet.nonce, 12); // 4. Copy Nonce (12 bytes).
    offset += 12;
    memcpy(destinationBuffer + offset, &packet.ciphertextLength, 2); // 5. Copy Ciphertext Length (2 bytes).
    offset += 2;
    if (packet.ciphertextLength > kMaxPayloadLength) {
        return 0; // Exceeds safety bounds.
    }
    memcpy(destinationBuffer + offset, packet.ciphertext, packet.ciphertextLength); // 6. Copy Ciphertext (variable L bytes).
    offset += packet.ciphertextLength;
    memcpy(destinationBuffer + offset, packet.tag, 16); // 7. Copy Authentication Tag (16 bytes).
    offset += 16;
    return offset; // Returns total bytes written.
}

bool PacketHandler::Deserialize(const uint8_t* sourceBuffer, size_t length, SecurePacket& packet) {
    // Minimum possible packet length (with 0-byte ciphertext) according to specifications.
    const size_t kMinHeaderTagLength = 44;
    if (sourceBuffer == nullptr || length < kMinHeaderTagLength) { // Malformed or empty packet.
        return false;
    }
    size_t offset = 0;
    memcpy(packet.senderId, sourceBuffer + offset, 6); // 1. Extract Sender ID (6 bytes).
    offset += 6;
    memcpy(&packet.sessionId, sourceBuffer + offset, 4); // 2. Extract Session ID (4 bytes).
    offset += 4;
    memcpy(&packet.sequenceNumber, sourceBuffer + offset, 4); // 3. Extract Sequence Number (4 bytes).
    offset += 4;
    memcpy(packet.nonce, sourceBuffer + offset, 12); // 4. Extract Nonce (12 bytes).
    offset += 12;
    memcpy(&packet.ciphertextLength, sourceBuffer + offset, 2); // 5. Extract Ciphertext Length (2 bytes).
    offset += 2;
    if (packet.ciphertextLength > kMaxPayloadLength || length < (offset + packet.ciphertextLength + 16)) { // Validate ciphertext length against buffer bounds and max limit to know if there is overflow risk or the lenght field is corrupted.
        return false;
    }
    memcpy(packet.ciphertext, sourceBuffer + offset, packet.ciphertextLength); // 6. Extract Ciphertext (L bytes).
    offset += packet.ciphertextLength;
    memcpy(packet.tag, sourceBuffer + offset, 16); // 7. Extract Authentication Tag (16 bytes).
    offset += 16;
    return true; // Successfully parsed.
}