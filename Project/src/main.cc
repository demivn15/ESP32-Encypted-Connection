#include <Arduino.h>
#include <WiFi.h>
#include "crypto_manager.h"
#include "packet_handler.h"
#include "replay_protection.h"
#include "wireless_driver.h"

static CryptoManager cryptoManager;
static ReplayProtection replayProtection;
static WirelessDriver wirelessDriver;

static uint32_t currentSessionId = 54321;
static uint32_t outgoingSequenceNumber = 0;
// Note: You can change this to your second ESP32's actual MAC address if you want strict unicast, 
// or keep broadcast {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} for local testing.
static uint8_t targetPeerMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

void HandleIncomingPacket(const uint8_t* senderMac, const uint8_t* data, size_t length);
void SendHandshakeRequest();
void PrintHex(const uint8_t* data, size_t length);

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n==================================================");
    Serial.println("[INFO] ESP32 Secure P2P IoT System Initializing...");
    
    uint8_t localMac[6];
    WiFi.macAddress(localMac);
    Serial.printf("[INFO] Local Device MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        localMac[0], localMac[1], localMac[2], localMac[3], localMac[4], localMac[5]);
    Serial.println("==================================================");

    if (!cryptoManager.Initialize()) {
        Serial.println("[ERROR] CryptoManager initialization failed!");
        return;
    }

    if (!wirelessDriver.Initialize()) {
        Serial.println("[ERROR] WirelessDriver initialization failed!");
        return;
    }

    wirelessDriver.SetReceiveCallback(HandleIncomingPacket);
    wirelessDriver.RegisterPeer(targetPeerMac);

    Serial.println("[CLI] Type 'connect' to initiate ECDH key exchange handshake.");
    Serial.println("[CLI] Type any message and press Enter to send securely.\n");
}

void loop() {
    if (Serial.available() > 0) {
        String inputMessage = Serial.readStringUntil('\n');
        inputMessage.trim();

        if (inputMessage.length() > 0) {
            if (inputMessage.equalsIgnoreCase("connect")) {
                SendHandshakeRequest();
                return;
            }

            if (inputMessage.length() > kMaxPayloadLength) {
                Serial.println("[ERROR] Message exceeds maximum allowed payload length!");
                return;
            }

            Serial.println("\n--------------------------------------------------");
            Serial.printf("[TX] Preparing Plaintext Message: \"%s\"\n", inputMessage.c_str());

            SecurePacket packet;
            packet.type = PacketType::kData;
            packet.sessionId = currentSessionId;
            packet.sequenceNumber = ++outgoingSequenceNumber;

            uint8_t localMac[6];
            WiFi.macAddress(localMac);
            memcpy(packet.senderId, localMac, 6);

            memset(packet.nonce, 0, sizeof(packet.nonce));
            uint32_t timestamp = static_cast<uint32_t>(millis());
            memcpy(packet.nonce, &timestamp, 4);
            memcpy(packet.nonce + 4, &packet.sequenceNumber, 4);

            Serial.printf("[TX] Generated Nonce (12 bytes): ");
            PrintHex(packet.nonce, 12);
            Serial.printf("[TX] Assigned Sequence Number (SEQ): %u\n", packet.sequenceNumber);

            packet.payloadLength = static_cast<uint16_t>(inputMessage.length());
            
            // Encrypt using AES-128-GCM
            bool encryptionSuccess = cryptoManager.Encrypt(
                reinterpret_cast<const uint8_t*>(inputMessage.c_str()),
                packet.payloadLength,
                packet.nonce,
                sizeof(packet.nonce),
                packet.payload,
                packet.tag
            );

            if (!encryptionSuccess) {
                Serial.println("[ERROR] Encryption failed! Have you completed the 'connect' handshake?");
                return;
            }

            Serial.printf("[TX] Ciphertext (C, %u bytes): ", packet.payloadLength);
            PrintHex(packet.payload, packet.payloadLength);

            Serial.printf("[TX] Authentication Tag (TAG, 16 bytes): ");
            PrintHex(packet.tag, 16);

            uint8_t serializedBuffer[256];
            size_t serializedSize = PacketHandler::Serialize(packet, serializedBuffer, sizeof(serializedBuffer));

            if (serializedSize > 0 && wirelessDriver.Send(targetPeerMac, serializedBuffer, serializedSize)) {
                Serial.println("[INFO] Secure packet successfully broadcasted over the air.");
            } else {
                Serial.println("[ERROR] Wireless transmission failed.");
            }
            Serial.println("--------------------------------------------------");
        }
    }
    delay(50);
}

void SendHandshakeRequest() {
    Serial.println("\n--------------------------------------------------");
    Serial.println("[HANDSHAKE] Generating local ephemeral ECDH key pair...");

    uint8_t publicKey[65];
    size_t publicKeyLength = 0;

    if (!cryptoManager.GenerateEcdhKeyPair(publicKey, &publicKeyLength)) {
        Serial.println("[ERROR] Failed to generate local ECDH key pair.");
        return;
    }

    Serial.printf("[HANDSHAKE] Local Public Key Generated (%u bytes):\n", publicKeyLength);
    PrintHex(publicKey, publicKeyLength);

    SecurePacket packet;
    packet.type = PacketType::kHandshake;
    packet.sessionId = currentSessionId;
    packet.sequenceNumber = ++outgoingSequenceNumber;

    uint8_t localMac[6];
    WiFi.macAddress(localMac);
    memcpy(packet.senderId, localMac, 6);
    memset(packet.nonce, 0, sizeof(packet.nonce));

    packet.payloadLength = static_cast<uint16_t>(publicKeyLength);
    memcpy(packet.payload, publicKey, publicKeyLength);
    memset(packet.tag, 0, 16);

    uint8_t serializedBuffer[256];
    size_t serializedSize = PacketHandler::Serialize(packet, serializedBuffer, sizeof(serializedBuffer));

    if (serializedSize > 0 && wirelessDriver.Send(targetPeerMac, serializedBuffer, serializedSize)) {
        Serial.println("[HANDSHAKE] Public key successfully transmitted over the air to peer.");
    } else {
        Serial.println("[ERROR] Failed to broadcast handshake packet.");
    }
    Serial.println("--------------------------------------------------");
}

void HandleIncomingPacket(const uint8_t* senderMac, const uint8_t* data, size_t length) {
    Serial.println("\n--------------------------------------------------");
    Serial.printf("[RX] Incoming transmission from [%02X:%02X:%02X:%02X:%02X:%02X] (%u bytes)\n",
        senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5], length);

    SecurePacket packet;
    if (!PacketHandler::Deserialize(data, length, packet)) {
        Serial.println("[SECURITY ERROR] Deserialization failed. Malformed packet dropped.");
        Serial.println("--------------------------------------------------");
        return;
    }

    // 1. Handle Handshake Packet
    if (packet.type == PacketType::kHandshake) {
        Serial.println("[RX TYPE] Received Handshake Packet (ECDH Public Key)");
        Serial.printf("[RX] Peer Public Key Received (%u bytes):\n", packet.payloadLength);
        PrintHex(packet.payload, packet.payloadLength);

        Serial.println("[HANDSHAKE] Computing shared secret and deriving session key...");
        bool success = cryptoManager.ComputeSharedSecret(packet.payload, packet.payloadLength);
        if (success) {
            Serial.println("[SUCCESS] ECDH shared secret computed successfully! AES-128-GCM session key active.");
        } else {
            Serial.println("[ERROR] Failed to compute ECDH shared secret.");
        }
        Serial.println("--------------------------------------------------");
        return;
    }

    // 2. Handle Data Packet
    Serial.println("[RX TYPE] Received Encrypted Data Packet");
    Serial.printf("[RX] Session ID: %u (Expected: %u)\n", packet.sessionId, currentSessionId);
    if (packet.sessionId != currentSessionId) {
        Serial.println("[SECURITY ERROR] Session ID mismatch. Packet dropped.");
        Serial.println("--------------------------------------------------");
        return;
    }

    Serial.printf("[RX] Sequence Number (SEQ): %u\n", packet.sequenceNumber);
    if (!replayProtection.ValidateAndUpdate(packet.sequenceNumber)) {
        Serial.println("[SECURITY ERROR] Replay attack or duplicate sequence number detected! Packet dropped.");
        Serial.println("--------------------------------------------------");
        return;
    }

    Serial.printf("[RX] Received Nonce: ");
    PrintHex(packet.nonce, 12);

    Serial.printf("[RX] Ciphertext (C, %u bytes): ", packet.payloadLength);
    PrintHex(packet.payload, packet.payloadLength);

    Serial.printf("[RX] Authentication Tag (TAG): ");
    PrintHex(packet.tag, 16);

    uint8_t decryptedPayload[kMaxPayloadLength];
    memset(decryptedPayload, 0, sizeof(decryptedPayload));

    bool decryptionSuccess = cryptoManager.Decrypt(
        packet.payload,
        packet.payloadLength,
        packet.nonce,
        sizeof(packet.nonce),
        packet.tag,
        sizeof(packet.tag),
        decryptedPayload
    );

    if (!decryptionSuccess) {
        Serial.println("[SECURITY ERROR] AES-GCM Tag verification failed! Data was tampered with or key is invalid. Packet dropped.");
        Serial.println("--------------------------------------------------");
        return;
    }

    Serial.println("[SUCCESS] AEAD Integrity Verified & Decryption Successful!");
    Serial.printf("[DECRYPTED PLAINTEXT] \"%s\"\n", reinterpret_cast<char*>(decryptedPayload));
    Serial.println("--------------------------------------------------");
}

void PrintHex(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}