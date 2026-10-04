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

// Dynamic MAC learning: Starts as broadcast, updates automatically upon receiving a packet
static uint8_t targetPeerMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 

// Serial input buffer for live typing and local echo
static String inputBuffer = "";

// Forward declarations
void HandleIncomingPacket(const uint8_t* senderMac, const uint8_t* data, size_t length);
void SendHandshakeRequest();
void PrintHex(const uint8_t* data, size_t length);
void ProcessCommand(String inputMessage);

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

    Serial.println("[CLI] Type 'help' to see available commands & test options.\n");
    Serial.print("> "); // Initial prompt
}

void loop() {
    // Read serial characters live as you type them
    while (Serial.available() > 0) {
        char c = Serial.read();

        // Check for Enter key (Carriage Return '\r' or Newline '\n')
        if (c == '\n' || c == '\r') {
            Serial.println(); // Move to the next line on the terminal
            inputBuffer.trim();

            if (inputBuffer.length() > 0) {
                ProcessCommand(inputBuffer);
            }

            inputBuffer = ""; // Clear buffer for next command
            Serial.print("> "); // Print prompt again
        }
        else if (c == '\b' || c == 127) {
            // Handle Backspace key
            if (inputBuffer.length() > 0) {
                inputBuffer.remove(inputBuffer.length() - 1);
                Serial.print("\b \b"); // Erase character visually from terminal
            }
        }
        else {
            // Normal character: Append to buffer and echo back to Serial Monitor
            inputBuffer += c;
            Serial.print(c);
        }
    }
    delay(10);
}

void ProcessCommand(String inputMessage) {
    if (inputMessage.equalsIgnoreCase("help")) {
        Serial.println("\n--- ESP32 SECURE P2P TEST MENU ---");
        Serial.println("connect       : Perform ECDH key exchange handshake");
        Serial.println("test normal   : Send valid encrypted message over the air");
        Serial.println("test tamper   : Simulate ciphertext tampering & verify drop");
        Serial.println("test tag      : Simulate authentication tag corruption & verify drop");
        Serial.println("test replay   : Simulate replay attack (duplicate sequence number)");
        Serial.println("test inject   : Simulate cross-session / unauthorized injection");
        Serial.println("-----------------------------------");
    }
    else if (inputMessage.equalsIgnoreCase("connect")) {
        SendHandshakeRequest();
    }
    else if (inputMessage.equalsIgnoreCase("test normal")) {
        Serial.println("\n[TEST] Executing Over-The-Air Normal Secure Transmission...");
        String sampleMsg = "Hello Normal IoT World!";
        
        SecurePacket packet;
        packet.type = PacketType::kData;
        packet.sessionId = currentSessionId;
        packet.sequenceNumber = ++outgoingSequenceNumber;
        WiFi.macAddress(packet.senderId);
        
        memset(packet.nonce, 0, sizeof(packet.nonce));
        uint32_t ts = static_cast<uint32_t>(millis());
        memcpy(packet.nonce, &ts, 4);
        memcpy(packet.nonce + 4, &packet.sequenceNumber, 4);

        packet.payloadLength = static_cast<uint16_t>(sampleMsg.length());
        cryptoManager.Encrypt(reinterpret_cast<const uint8_t*>(sampleMsg.c_str()), 
                              packet.payloadLength, packet.nonce, 12, 
                              packet.payload, packet.tag);

        uint8_t rawBuf[256];
        size_t sz = PacketHandler::Serialize(packet, rawBuf, sizeof(rawBuf));
        
        if (sz > 0 && wirelessDriver.Send(targetPeerMac, rawBuf, sz)) {
            Serial.println("[INFO] Normal test packet sent over the air.");
        } else {
            Serial.println("[ERROR] Wireless transmission failed.");
        }
    }
    else if (inputMessage.equalsIgnoreCase("test tamper")) {
        Serial.println("\n[TEST] Executing Over-The-Air Ciphertext Tampering Attack...");
        String sampleMsg = "Secret Sensor Data";
        
        SecurePacket packet;
        packet.type = PacketType::kData;
        packet.sessionId = currentSessionId;
        packet.sequenceNumber = ++outgoingSequenceNumber;
        WiFi.macAddress(packet.senderId);
        
        memset(packet.nonce, 0, 12);
        packet.payloadLength = static_cast<uint16_t>(sampleMsg.length());
        cryptoManager.Encrypt(reinterpret_cast<const uint8_t*>(sampleMsg.c_str()), 
                              packet.payloadLength, packet.nonce, 12, 
                              packet.payload, packet.tag);

        packet.payload[0] ^= 0xFF; // Malicious bit flip

        uint8_t rawBuf[256];
        size_t sz = PacketHandler::Serialize(packet, rawBuf, sizeof(rawBuf));
        
        if (sz > 0 && wirelessDriver.Send(targetPeerMac, rawBuf, sz)) {
            Serial.println("[INFO] Tampered packet sent over the air (Peer should drop it).");
        } else {
            Serial.println("[ERROR] Wireless transmission failed.");
        }
    }
    else if (inputMessage.equalsIgnoreCase("test tag")) {
        Serial.println("\n[TEST] Executing Over-The-Air Tag Corruption Attack...");
        String sampleMsg = "Critical Command: Open Valve";
        
        SecurePacket packet;
        packet.type = PacketType::kData;
        packet.sessionId = currentSessionId;
        packet.sequenceNumber = ++outgoingSequenceNumber;
        WiFi.macAddress(packet.senderId);
        
        memset(packet.nonce, 0, 12);
        packet.payloadLength = static_cast<uint16_t>(sampleMsg.length());
        cryptoManager.Encrypt(reinterpret_cast<const uint8_t*>(sampleMsg.c_str()), 
                              packet.payloadLength, packet.nonce, 12, 
                              packet.payload, packet.tag);

        packet.tag[0] ^= 0xAA; // Corrupt Auth Tag

        uint8_t rawBuf[256];
        size_t sz = PacketHandler::Serialize(packet, rawBuf, sizeof(rawBuf));
        
        if (sz > 0 && wirelessDriver.Send(targetPeerMac, rawBuf, sz)) {
            Serial.println("[INFO] Tag-corrupted packet sent over the air (Peer should drop it).");
        } else {
            Serial.println("[ERROR] Wireless transmission failed.");
        }
    }
    else if (inputMessage.equalsIgnoreCase("test replay")) {
        Serial.println("\n[TEST] Executing Over-The-Air Replay Attack Simulation...");
        
        SecurePacket packet;
        packet.type = PacketType::kData;
        packet.sessionId = currentSessionId;
        packet.sequenceNumber = 999; 
        WiFi.macAddress(packet.senderId);
        
        memset(packet.nonce, 0, 12);
        String msg = "Replay test message";
        packet.payloadLength = static_cast<uint16_t>(msg.length());
        cryptoManager.Encrypt(reinterpret_cast<const uint8_t*>(msg.c_str()), 
                              packet.payloadLength, packet.nonce, 12, 
                              packet.payload, packet.tag);

        uint8_t rawBuf[256];
        size_t sz = PacketHandler::Serialize(packet, rawBuf, sizeof(rawBuf));
        
        Serial.println("-> Sending packet first time (Peer should ACCEPT):");
        wirelessDriver.Send(targetPeerMac, rawBuf, sz);
        delay(100);

        Serial.println("-> Resending exact same packet second time (Peer should REJECT):");
        wirelessDriver.Send(targetPeerMac, rawBuf, sz);
    }
    else if (inputMessage.equalsIgnoreCase("test inject")) {
        Serial.println("\n[TEST] Executing Over-The-Air Cross-Session Injection...");
        
        SecurePacket packet;
        packet.type = PacketType::kData;
        packet.sessionId = 99999; // Forged Session ID
        packet.sequenceNumber = ++outgoingSequenceNumber;
        WiFi.macAddress(packet.senderId);
        
        memset(packet.nonce, 0, 12);
        String msg = "Forged unauthorized data";
        packet.payloadLength = static_cast<uint16_t>(msg.length());
        cryptoManager.Encrypt(reinterpret_cast<const uint8_t*>(msg.c_str()), 
                              packet.payloadLength, packet.nonce, 12, 
                              packet.payload, packet.tag);

        uint8_t rawBuf[256];
        size_t sz = PacketHandler::Serialize(packet, rawBuf, sizeof(rawBuf));
        
        if (sz > 0 && wirelessDriver.Send(targetPeerMac, rawBuf, sz)) {
            Serial.println("[INFO] Injected packet sent over the air (Peer should drop it).");
        } else {
            Serial.println("[ERROR] Wireless transmission failed.");
        }
    } 
    else {
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

        packet.payloadLength = static_cast<uint16_t>(inputMessage.length());
        
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
    // Automatically learn and lock onto the sender's real MAC address
    memcpy(targetPeerMac, senderMac, 6);
    wirelessDriver.RegisterPeer(targetPeerMac);

    Serial.println("\n--------------------------------------------------");
    Serial.printf("[RX] Incoming transmission from [%02X:%02X:%02X:%02X:%02X:%02X] (%u bytes)\n",
        senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5], length);

    SecurePacket packet;
    if (!PacketHandler::Deserialize(data, length, packet)) {
        Serial.println("[SECURITY ERROR] Deserialization failed. Malformed packet dropped.");
        Serial.println("--------------------------------------------------");
        Serial.print("> ");
        return;
    }

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
        Serial.print("> ");
        return;
    }

    Serial.println("[RX TYPE] Received Encrypted Data Packet");
    Serial.printf("[RX] Session ID: %u (Expected: %u)\n", packet.sessionId, currentSessionId);
    if (packet.sessionId != currentSessionId) {
        Serial.println("[SECURITY ERROR] Session ID mismatch. Packet dropped.");
        Serial.println("--------------------------------------------------");
        Serial.print("> ");
        return;
    }

    Serial.printf("[RX] Sequence Number (SEQ): %u\n", packet.sequenceNumber);
    if (!replayProtection.ValidateAndUpdate(packet.sequenceNumber)) {
        Serial.println("[SECURITY ERROR] Replay attack or duplicate sequence number detected! Packet dropped.");
        Serial.println("--------------------------------------------------");
        Serial.print("> ");
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
        Serial.print("> ");
        return;
    }

    Serial.println("[SUCCESS] AEAD Integrity Verified & Decryption Successful!");
    Serial.printf("[DECRYPTED PLAINTEXT] \"%s\"\n", reinterpret_cast<char*>(decryptedPayload));
    Serial.println("--------------------------------------------------");
    Serial.print("> ");
}

void PrintHex(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        Serial.printf("%02X ", data[i]);
    }
    Serial.println();
}