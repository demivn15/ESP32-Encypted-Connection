#include <Arduino.h>
#include <WiFi.h>

#include "crypto_manager.h"
#include "packet_handler.h"
#include "replay_protection.h"
#include "wireless_driver.h"

// Component instances mapping directly to our system architecture diagram
static CryptoManager cryptoManager;
static ReplayProtection replayProtection;
static WirelessDriver wirelessDriver;

// Application State
static uint32_t currentSessionId = 12345;
static uint32_t outgoingSequenceNumber = 0;
// Default target MAC address (set to broadcast FF:FF:FF:FF:FF:FF for local testing, or pair-specific MAC)
static uint8_t targetPeerMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

// Forward declaration for the wireless receive callback
void HandleIncomingPacket(const uint8_t* senderMac, const uint8_t* data, size_t length);

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n[INFO] Initializing Secure P2P IoT Communication System...");

    // 1. Initialize Cryptographic Engine
    if (!cryptoManager.Initialize()) {
        Serial.println("[ERROR] CryptoManager initialization failed!");
        return;
    }

    // 2. Initialize Wireless Driver & ESP-NOW Stack
    if (!wirelessDriver.Initialize()) {
        Serial.println("[ERROR] WirelessDriver initialization failed!");
        return;
    }

    // Register incoming packet callback handler
    wirelessDriver.SetReceiveCallback(HandleIncomingPacket);

    // 3. Register target peer device
    if (!wirelessDriver.RegisterPeer(targetPeerMac)) {
        Serial.println("[WARNING] Failed to register peer MAC address.");
    }

    Serial.println("[INFO] System initialized successfully.");
    Serial.println("[CLI] Type a message in the Serial Monitor and press Enter to transmit securely.");
}

void loop() {
    // Check for user input from the Serial CLI application layer
    if (Serial.available() > 0) {
        String inputMessage = Serial.readStringUntil('\n');
        inputMessage.trim();

        if (inputMessage.length() > 0) {
            if (inputMessage.length() > kMaxPayloadLength) {
                Serial.println("[ERROR] Message exceeds maximum allowed payload length!");
                return;
            }

            Serial.printf("[CLI] Preparing plaintext: \"%s\"\n", inputMessage.c_str());

            SecurePacket packet;
            packet.sessionId = currentSessionId;
            packet.sequenceNumber = ++outgoingSequenceNumber;

            // Fetch local ESP32 MAC address for ID_S
            uint8_t localMac[6];
            WiFi.macAddress(localMac);
            memcpy(packet.senderId, localMac, 6);

            // Generate a unique 96-bit (12-byte) nonce using system uptime and sequence
            memset(packet.nonce, 0, sizeof(packet.nonce));
            uint32_t timestamp = static_cast<uint32_t>(millis());
            memcpy(packet.nonce, &timestamp, 4);
            memcpy(packet.nonce + 4, &packet.sequenceNumber, 4);

            // Encrypt plaintext and generate authentication tag via AES-128-GCM
            packet.ciphertextLength = static_cast<uint16_t>(inputMessage.length());
            bool encryptionSuccess = cryptoManager.Encrypt(
                reinterpret_cast<const uint8_t*>(inputMessage.c_str()),
                packet.ciphertextLength,
                packet.nonce,
                sizeof(packet.nonce),
                packet.ciphertext,
                packet.tag
            );

            if (!encryptionSuccess) {
                Serial.println("[ERROR] AES-GCM encryption failed!");
                return;
            }

            // Serialize packet structure into a raw byte buffer
            uint8_t serializedBuffer[256];
            size_t serializedSize = PacketHandler::Serialize(packet, serializedBuffer, sizeof(serializedBuffer));

            if (serializedSize == 0) {
                Serial.println("[ERROR] Packet serialization failed!");
                return;
            }

            // Transmit raw bytes over the air via ESP-NOW wireless driver
            bool sendSuccess = wirelessDriver.Send(targetPeerMac, serializedBuffer, serializedSize);
            if (sendSuccess) {
                Serial.println("[INFO] Secure packet successfully transmitted over the air.");
            } else {
                Serial.println("[ERROR] Wireless transmission failed!");
            }
        }
    }
    delay(50);
}

void HandleIncomingPacket(const uint8_t* senderMac, const uint8_t* data, size_t length) {
    Serial.println("\n[RX] Incoming wireless transmission detected. Executing security verification pipeline...");

    // 1. Deserialize raw byte buffer back into the SecurePacket structure
    SecurePacket packet;
    if (!PacketHandler::Deserialize(data, length, packet)) {
        Serial.println("[SECURITY ERROR] Packet deserialization failed. Malformed packet dropped.");
        return;
    }

    // 2. Validate Session ID (SID) and Session Binding
    if (packet.sessionId != currentSessionId) {
        Serial.println("[SECURITY ERROR] Session ID mismatch! Cross-session injection dropped.");
        return;
    }

    // 3. Verify Sequence Number (Replay Protection Sliding Window)
    if (!replayProtection.ValidateAndUpdate(packet.sequenceNumber)) {
        Serial.println("[SECURITY ERROR] Replay attack or duplicate sequence number detected! Packet dropped.");
        return;
    }

    // 4. Authenticated Decryption & Tag Verification (AES-128-GCM)
    uint8_t decryptedPayload[kMaxPayloadLength];
    memset(decryptedPayload, 0, sizeof(decryptedPayload));

    bool decryptionSuccess = cryptoManager.Decrypt(
        packet.ciphertext,
        packet.ciphertextLength,
        packet.nonce,
        sizeof(packet.nonce),
        packet.tag,
        sizeof(packet.tag),
        decryptedPayload
    );

    if (!decryptionSuccess) {
        Serial.println("[SECURITY ERROR] AES-GCM Authentication Tag verification failed! Data integrity compromised. Packet dropped.");
        return;
    }

    // 5. Success! Output decrypted plaintext to Application CLI
    Serial.printf("[SUCCESS] Verified & Decrypted Message from [%02X:%02X:%02X:%02X:%02X:%02X]: \"%s\"\n",
        senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5],
        reinterpret_cast<char*>(decryptedPayload));
}