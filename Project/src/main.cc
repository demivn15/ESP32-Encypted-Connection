#include <Arduino.h>
#include <WiFiManager.h>
#include <WiFi.h>

// void ConfigModeCallback(WiFiManager *wm) {
//   while (true) {
//     delay(1000);
//     digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
//   }
// }

void setup() {
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, LOW);
  WiFi.mode(WIFI_STA);
  WiFiManager wm;
  // wm.setAPCallback(ConfigModeCallback);
  wm.resetSettings();
  bool res;
  res = wm.autoConnect("AutoConnectAP", "password");
  if (!res) {
    Serial.println("Failed to connect ESP32.");
    digitalWrite(LED_BUILTIN, LOW);
  } else {
    Serial.println("ESP32 connected successfully.");
    digitalWrite(LED_BUILTIN, HIGH);
  }
  WiFiClient client;
  if (!client.connect("192.168.0.6", 5000)) {
    Serial.println("Connection to server failed.");
    delay(1000);
    return;
  }
  client.print("Hello from ESP32!");
  client.stop();
}

void loop() {
}