#include "wireless_driver.h"
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <cstring>

QueueHandle_t WirelessDriver::queue_ = nullptr;
std::atomic<uint32_t> WirelessDriver::dropped_(0);
bool WirelessDriver::Initialize() {
    WiFi.mode(WIFI_STA); WiFi.disconnect(false, false); WiFi.setSleep(false);
    delay(100);
    if (esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
    queue_ = xQueueCreate(8, sizeof(Frame));
    if (!queue_ || esp_now_init() != ESP_OK) return false;
    if (esp_now_register_recv_cb(OnDataReceived) != ESP_OK) return false;
    initialized_ = true; return true;
}
bool WirelessDriver::Send(const Mac &peer, const Bytes &data) {
    if (!initialized_ || data.empty() || data.size() > kMaxWireLength) return false;
    if (!esp_now_is_peer_exist(peer.data())) {
        esp_now_peer_info_t info{};
        std::memcpy(info.peer_addr, peer.data(), 6);
        info.channel = 1; info.ifidx = WIFI_IF_STA; info.encrypt = false;
        if (esp_now_add_peer(&info) != ESP_OK) return false;
    }
    // ESP_OK indica encolado, no confirmacion de recepcion por la aplicacion.
    return esp_now_send(peer.data(), data.data(), data.size()) == ESP_OK;
}
bool WirelessDriver::Read(Mac &source, Bytes &data) {
    Frame frame;
    if (!queue_ || xQueueReceive(queue_, &frame, 0) != pdTRUE) return false;
    std::copy(frame.mac, frame.mac+6, source.begin());
    data.assign(frame.data, frame.data+frame.length); return true;
}
void WirelessDriver::OnDataReceived(const uint8_t *mac, const uint8_t *data, int length) {
    if (!queue_ || !mac || !data || length <= 0 || length > int(kMaxWireLength)) return;
    Frame frame{};
    std::memcpy(frame.mac, mac, 6); frame.length = uint16_t(length);
    std::memcpy(frame.data, data, length);
    if (xQueueSend(queue_, &frame, 0) != pdTRUE) dropped_.fetch_add(1);
}
