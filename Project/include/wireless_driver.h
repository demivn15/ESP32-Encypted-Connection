#ifndef WIRELESS_DRIVER_H
#define WIRELESS_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#include <Arduino.h>

// Callback function signature for when a secure packet is received over the air
typedef void (*PacketReceiveCallback)(const uint8_t* senderMac, const uint8_t* data, size_t length);

class WirelessDriver {
public:
    WirelessDriver();
    // Initializes Wi-Fi station mode and ESP-NOW framework
    bool Initialize();
    // Registers a peer device using its 6-byte MAC address
    bool RegisterPeer(const uint8_t* peerMac);
    // Transmits a raw serialized packet buffer to a target peer via ESP-NOW
    bool Send(const uint8_t* peerMac, const uint8_t* data, size_t length);
    // Sets the callback function invoked when data arrives from the air
    void SetReceiveCallback(PacketReceiveCallback callback);
private:
    // Internal static callback trampoline required by ESP-NOW C-API
    static void OnDataReceived(const uint8_t* macAddr, const uint8_t* incomingData, int dataLen);
    static PacketReceiveCallback receiveCallback_;
    bool isInitialized_;
};

#endif  // WIRELESS_DRIVER_H