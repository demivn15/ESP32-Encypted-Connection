#include "replay_protection.h"

ReplayProtection::ReplayProtection() {
    Reset();
}

void ReplayProtection::Reset() {
    highestSequenceNumber_ = 0;
    bitmask_ = 0;
    isInitialized_ = false;
}

bool ReplayProtection::ValidateAndUpdate(uint32_t incomingSequenceNumber) {
    if (!isInitialized_) { // 1. If this is the very first packet of the session, initialize baseline.
        highestSequenceNumber_ = incomingSequenceNumber;
        bitmask_ = 1; // Mark current bit as seen.
        isInitialized_ = true;
        return true;
    }
    if (incomingSequenceNumber > highestSequenceNumber_) { // 2. Case A: Incoming sequence number is newer than our highest seen.
        uint32_t diff = incomingSequenceNumber - highestSequenceNumber_;
        if (diff < kSlidingWindowSize) {
            bitmask_ = (bitmask_ << diff) | 1; // Shift bitmask left by the difference and mark new packet.
        } else {
            bitmask_ = 1; // Jumped way ahead, reset window bitmask completely for the new high watermark.
        }
        highestSequenceNumber_ = incomingSequenceNumber;
        return true;
    }
    int32_t diff = static_cast<int32_t>(highestSequenceNumber_) - static_cast<int32_t>(incomingSequenceNumber); // 3. Case B: Incoming sequence number is older or equal.
    if (diff >= static_cast<int32_t>(kSlidingWindowSize)) { // If it falls outside the sliding window span, it's too old (replay / stale)
        return false; 
    }
    uint64_t bit = (1ULL << diff); // Check if it's a duplicate (bit already set in the window)
    if ((bitmask_ & bit) != 0) { // Replay detected! Duplicate packet.
        return false;
    }
    bitmask_ |= bit; // Mark this valid older packet as received in the bitmask
    return true;
}