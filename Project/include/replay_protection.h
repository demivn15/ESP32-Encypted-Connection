#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stddef.h>

class ReplayProtection {
public:
    ReplayProtection();
    // Resets tracker state (called during a new ECDH session handshake).
    void Reset();
    // Validates an incoming sequence number against replay attacks.
    bool ValidateAndUpdate(uint32_t incomingSequenceNumber);
private:
    static constexpr uint32_t kSlidingWindowSize = 64;
    // Highest valid SEQ seen so far.
    uint32_t highestSequenceNumber_;
    // Bitmask tracking received packets within the window.
    uint64_t bitmask_;
    // Tracks if the first packet has been received.
    bool isInitialized_;
};

#endif