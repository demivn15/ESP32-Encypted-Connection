#include "wireless_driver.h"

#include <esp_now.h>
#include <WiFi.h>

// Initialize static callback pointer
PacketReceiveCallback WirelessDriver::receiveCallback_ = nullptr;
WirelessDriver::WirelessDriver() : isInitialized_(false) {}

bool WirelessDriver::Initialize() { // ESP-NOW requires Wi-Fi to be initialized in Station mode.
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_now_init() != ESP_OK) { // ESP-NOW initialization failed.
        return false;
    }
    esp_now_register_recv_cb(WirelessDriver::OnDataReceived); // Register global receive callback wrapper.
    isInitialized_ = true;
    return true;
}

bool WirelessDriver::RegisterPeer(const uint8_t* peerMac) {
    if (!isInitialized_ || peerMac == nullptr) {
        return false;
    }
    esp_now_peer_info_t peerInfo = {};
    memcpy(peerInfo.peer_addr, peerMac, 6);
    peerInfo.channel = 0;     // Use current active Wi-Fi channel.
    peerInfo.encrypt = false; // We handle our own layer-2 AEAD encryption (AES-128-GCM).
    if (!esp_now_is_peer_exist(peerMac)) { // Check if peer is already registered; if not, add it.
        if (esp_now_add_peer(&peerInfo) != ESP_OK) {
            return false;
        }
    }
    return true;
}

bool WirelessDriver::Send(const uint8_t* peerMac, const uint8_t* data, size_t length) {
    if (!isInitialized_ || peerMac == nullptr || data == nullptr || length == 0) {
        return false;
    }
    esp_err_t result = esp_now_send(peerMac, data, length);
    return (result == ESP_OK);
}

void WirelessDriver::SetReceiveCallback(PacketReceiveCallback callback) {
    receiveCallback_ = callback;
}

void WirelessDriver::OnDataReceived(const uint8_t* macAddr, const uint8_t* incomingData, int dataLen) {
    if (receiveCallback_ != nullptr && incomingData != nullptr && dataLen > 0) { // Forward received bytes up to our application/packet pipeline.
        receiveCallback_(macAddr, incomingData, static_cast<size_t>(dataLen));
    }
}