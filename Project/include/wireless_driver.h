#pragma once
#include "packet_handler.h"
#include <Arduino.h>
#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

// El callback WiFi solo copia a una cola. Crypto y Serial se ejecutan en loop().
class WirelessDriver {
    struct Frame { uint8_t mac[6]; uint16_t length; uint8_t data[kMaxWireLength]; };
    static QueueHandle_t queue_;
    static std::atomic<uint32_t> dropped_;
    static void OnDataReceived(const uint8_t *, const uint8_t *, int);
    bool initialized_ = false;
public:
    bool Initialize();
    bool Send(const Mac &peer, const Bytes &data);
    bool Read(Mac &source, Bytes &data);
    uint32_t Dropped() const { return dropped_.load(); }
};
