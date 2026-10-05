#include <Arduino.h>
#include <WiFi.h>
#include <memory>
#include <cstring>
#include <mbedtls/platform_util.h>
#include "session.h"
#include "wireless_driver.h"
#include "text_rtt.h"
#ifndef DEVICE_ROGUE
#include "pair_secret.h"
#endif
#ifndef DEVICE_ROLE
#define DEVICE_ROLE 1
#endif

WirelessDriver wireless;
std::unique_ptr<Session> session;
const Mac broadcast{{255,255,255,255,255,255}};
std::string keyboard;
bool overflow = false, demo = true;
uint32_t txCount = 0, rxCount = 0, rejectCount = 0, handshakeSince = 0, retrySince = 0;
uint32_t pingSince = 0;
Bytes pendingPing, pendingTextWire, lastConfirmedText;
TextRtt textRtt;

void printHex(const Bytes &value) {
    for (uint8_t b : value) Serial.printf("%02X", b);
    Serial.println();
}
void showPacket(const Bytes &wire) {
    SecurePacket p;
    if (!demo || !PacketHandler::Deserialize(wire, p)) return;
    Serial.printf("[WIRE] tipo=%u (%s) rol=%u (%c) SEQ=%lu bytes=%u SID=", uint8_t(p.type),
        PacketHandler::TypeName(p.type), p.role, p.role == 1 ? 'A' : 'B', (unsigned long)p.sequence, (unsigned)wire.size());
    printHex(Bytes(p.sid.begin(), p.sid.end()));
    if (p.type == PacketType::Hello || p.type == PacketType::Response) {
        Serial.print("[PUBLICA ECDH] "); printHex(Bytes(p.payload.begin(), p.payload.begin()+65));
    } else if (p.type == PacketType::Text) {
        Serial.print("[CIPHERTEXT] "); printHex(p.payload);
        Serial.print("[TAG GCM] "); printHex(p.tag);
    }
}
void metricHeader() {
    Serial.println("========== GUIA DE METRICAS ==========");
    Serial.println("TX = envio de texto | RX = recepcion de texto | RTT = ida/vuelta del ping");
    Serial.println("PING_TX/RX y PONG_TX/RX = medidas del ping/pong separadas del texto");
    Serial.println("ATTACK_TX = envio alterado | REJECT = paquete rechazado");
    Serial.println("RTT_TEXT = ida/vuelta del texto con ACK cifrado; ACK_TX/RX = confirmacion");
    Serial.println("Columnas despues de METRIC:");
    Serial.println("1 tipo | 2 texto (bytes) | 3 paquete (bytes)");
    Serial.println("4 cifrar/preparar (us) | 5 verificar/descifrar (us) | 6 ida/vuelta (us)");
    Serial.println("us = microsegundos; 1000 us = 1 ms. Paquete excluye cabeceras de radio.");
    Serial.println("0 en un tiempo no aplicable = N/A. TX no confirma entrega.");
    Serial.println("/metricas repite esta guia. /demo off oculta las explicaciones por mensaje.");
    Serial.println("METRIC,direccion,plaintext_bytes,packet_bytes,encrypt_us,verify_decrypt_us,rtt_us");
}
void metric(const char *direction, size_t plain, size_t wire, uint32_t encrypt, uint32_t verify, uint32_t rtt) {
    // Se conserva el CSV para resumir_metricas.ps1. La explicacion se imprime
    // despues de medir y se puede ocultar con /demo off para rendimiento.
    Serial.printf("METRIC,%s,%u,%u,%lu,%lu,%lu\n", direction, (unsigned)plain, (unsigned)wire,
        (unsigned long)encrypt, (unsigned long)verify, (unsigned long)rtt);
    if (!demo) return;
    if (std::strcmp(direction, "TX") == 0 || std::strcmp(direction, "ATTACK_TX") == 0) {
        Serial.printf("[METRICA %s] texto=%u B | paquete=%u B | cifrar/preparar=%lu us | verificar=N/A | RTT=N/A\n",
            direction, (unsigned)plain, (unsigned)wire, (unsigned long)encrypt);
    } else if (std::strcmp(direction, "RX") == 0) {
        Serial.printf("[METRICA RX] texto=%u B | paquete=%u B | cifrar=N/A | verificar/descifrar=%lu us | RTT=N/A\n",
            (unsigned)plain, (unsigned)wire, (unsigned long)verify);
    } else if (std::strcmp(direction, "RTT") == 0 || std::strcmp(direction, "RTT_TEXT") == 0) {
        Serial.printf("[METRICA %s] texto=%u B | ida y vuelta verificada=%lu us (%lu.%03lu ms)\n",
            direction, (unsigned)plain, (unsigned long)rtt, (unsigned long)(rtt/1000), (unsigned long)(rtt%1000));
    } else if (std::strcmp(direction, "REJECT") == 0) {
        Serial.printf("[METRICA REJECT] paquete=%u B | validar hasta rechazo=%lu us | texto=N/A\n",
            (unsigned)wire, (unsigned long)verify);
    }
}
bool sendProtected(PacketType type, const Bytes &plain, const std::string &attack = "") {
    if (type == PacketType::Text && attack.empty() && !pendingPing.empty()) {
        Serial.println("[INFO] Espera la respuesta del ping antes de medir otro texto."); return false;
    }
    if (type == PacketType::Text && attack.empty() && textRtt.Pending()) {
        Serial.println("[INFO] Espera CONFIRMADO o TIMEOUT antes del siguiente texto."); return false;
    }
    uint32_t start = micros(); Bytes wire;
    if (!session || !session->Send(type, plain, wire)) {
        Serial.println("[ERROR] Falta sesion confirmada, longitud invalida o contador agotado."); return false;
    }
    uint32_t elapsed = micros()-start;
    if (!attack.empty()) {
        SecurePacket p; PacketHandler::Deserialize(wire, p);
        if (attack == "ciphertext" && !p.payload.empty()) p.payload[0] ^= 1;
        else if (attack == "tag") p.tag.back() ^= 1;
        else if (attack == "forged") {
            p.payload = CryptoManager::Random(p.payload.size()); p.tag = CryptoManager::Random(16);
        } else if (attack == "sender") p.sender[0] ^= 1;
        else if (attack == "sid") p.sid[0] ^= 1;
        else if (attack == "seq") {
            p.sequence += 100;
            for (int i = 0; i < 4; ++i) p.nonce[11-i] = uint8_t(p.sequence >> (8*i));
        } else { Serial.println("[ERROR] Ataque invalido."); return false; }
        if (!PacketHandler::Serialize(p, wire)) return false;
        Serial.printf("[ATTACK] %s: registro alterado deliberadamente.\n", attack.c_str());
    }
    if (!wireless.Send(session->Peer(), wire)) { Serial.println("[ERROR] No se pudo encolar en ESP-NOW."); return false; }
    ++txCount;
    if (type == PacketType::Text && attack.empty()) {
        SecurePacket packet; PacketHandler::Deserialize(wire, packet);
        pendingTextWire = wire;
        textRtt.Start(packet.sequence, start, plain.size(), wire.size());
    }
    const char *direction = type == PacketType::Text ? "TX" : type == PacketType::Ping ? "PING_TX" : "PONG_TX";
    metric(attack.empty() ? direction : "ATTACK_TX", plain.size(), wire.size(), elapsed, 0, 0);
    if (demo && type == PacketType::Text && attack.empty()) {
        Serial.print("[ORIGINAL] "); Serial.write(plain.data(), plain.size()); Serial.println();
    }
    showPacket(wire);
    Serial.println("[TX] Encolado. La recepcion se comprueba en el otro monitor.");
    return true;
}
void help() {
    Serial.println("connect: A inicia; B responde automaticamente. /reset: usar en AMBAS placas.");
    Serial.println("Texto + Enter (max.128 bytes UTF-8). /ping /stats /metricas /demo on /demo off /help");
    Serial.println("/attack ciphertext texto | /attack tag texto | /attack forged texto");
    Serial.println("/attack sender texto | /attack sid texto | /attack seq texto | /attack replay");
    Serial.println("Cada texto recibe ACK cifrado y RTT_TEXT. Espera CONFIRMADO antes del siguiente.");
}
void command(const std::string &input) {
    if (!session) return;
    if (input == "/help") { help(); return; }
    if (input == "/metricas") { metricHeader(); return; }
    if (input == "/reset") {
        session->Reset(); pendingPing.clear(); pendingTextWire.clear(); lastConfirmedText.clear(); textRtt.Clear(); handshakeSince = 0;
        Serial.println("[RESET] Sesion local borrada. Reinicia/reset tambien al otro extremo."); return;
    }
    if (input == "/stats") {
        Serial.printf("TX=%lu RX=%lu REJECT=%lu heap_libre=%lu heap_minimo=%lu cola_descartados=%lu estado=%u\n",
            (unsigned long)txCount, (unsigned long)rxCount, (unsigned long)rejectCount,
            (unsigned long)ESP.getFreeHeap(), (unsigned long)ESP.getMinFreeHeap(),
            (unsigned long)wireless.Dropped(), unsigned(session->Status()));
        const char *name = session->Status() == State::Idle ? "Sin sesion" : session->Status() == State::WaitResponse ?
            "Esperando RESPONSE" : session->Status() == State::WaitReady ? "Esperando READY" : "Sesion segura establecida";
        Serial.printf("[ESTADO] %s | demo=%s | texto_pendiente=%s\n", name, demo ? "ON" : "OFF", textRtt.Pending() ? "SI" : "NO"); return;
    }
    if (input == "/demo on" || input == "/demo off") {
        demo = input == "/demo on"; Serial.printf("[DEMO] %s\n", demo ? "ON: muestra cifrado y explicaciones" : "OFF: medidas con menos impresion"); return;
    }
    if (input == "connect") {
        if (DEVICE_ROLE != 1) { Serial.println("[INFO] B espera el connect de A."); return; }
        Bytes hello; uint32_t startedAt = millis();
        if (!session->Start(hello)) { Serial.println("[ERROR] Usa /reset en ambas antes de otra sesion."); return; }
        handshakeSince = startedAt; retrySince = millis();
        if (!wireless.Send(broadcast, hello)) { session->Reset(); Serial.println("[ERROR] No se pudo enviar HELLO."); return; }
        Serial.println("[HANDSHAKE] HELLO autenticado enviado; esperando B."); showPacket(hello); return;
    }
    if (input == "/ping") {
        if (textRtt.Pending()) { Serial.println("[INFO] Espera CONFIRMADO antes de medir el ping."); return; }
        if (!pendingPing.empty()) { Serial.println("[INFO] Espera el ping pendiente."); return; }
        pendingPing = CryptoManager::Random(8); pingSince = micros();
        if (pendingPing.size() != 8 || !sendProtected(PacketType::Ping, pendingPing)) pendingPing.clear();
        return;
    }
    if (input == "/attack replay") {
        if (lastConfirmedText.empty()) { Serial.println("[ERROR] Envia texto normal y espera CONFIRMADO antes del replay."); return; }
        if (wireless.Send(session->Peer(), lastConfirmedText)) Serial.println("[ATTACK] Texto previamente confirmado capturado y reenviado sin modificar.");
        return;
    }
    if (input.compare(0,8,"/attack ") == 0) {
        size_t space = input.find(' ',8);
        std::string mode = input.substr(8, space == std::string::npos ? space : space-8);
        if (mode != "ciphertext" && mode != "tag" && mode != "forged" && mode != "sender" && mode != "sid" && mode != "seq") {
            Serial.println("[ERROR] Modo desconocido; /help."); return;
        }
        std::string message = space == std::string::npos ? "mensaje de ataque" : input.substr(space+1);
        if (message.empty() || message.size() > kMaxPayloadLength) { Serial.println("[ERROR] Usa de 1 a 128 bytes."); return; }
        sendProtected(PacketType::Text, Bytes(message.begin(),message.end()), mode); return;
    }
    if (!input.empty() && input[0] == '/') { Serial.println("[ERROR] Comando desconocido; /help."); return; }
    sendProtected(PacketType::Text, Bytes(input.begin(), input.end()));
}
void readKeyboard() {
    while (Serial.available()) {
        char c = char(Serial.read());
        if (c == '\r') continue;
        if (c != '\n') {
            // Comandos llevan un prefijo adicional al limite de texto.
            if (keyboard.size() < 180) keyboard += c; else overflow = true;
            continue;
        }
        std::string input; input.swap(keyboard);
        if (overflow) { overflow = false; Serial.println("[ERROR] Entrada demasiado larga."); continue; }
        command(input);
    }
}
void receive(const Mac &mac, const Bytes &wire) {
    State before = session->Status(); uint32_t receivedAt = millis(), start = micros();
    ReceiveResult result = session->Receive(mac, wire);
    uint32_t verifiedAt = micros(), elapsed = verifiedAt-start;
    if (result.event == Event::Rejected) {
        ++rejectCount; Serial.printf("[REJECT] %s; no se entrega texto.\n", result.reason.c_str());
        metric("REJECT", 0, wire.size(), 0, elapsed, 0); return;
    }
    if (!result.reply.empty() && !wireless.Send(mac, result.reply)) Serial.println("[ERROR] Respuesta de handshake no encolada; se reintentara.");
    if (result.event == Event::Handshake) {
        if (before == State::Idle) handshakeSince = receivedAt;
        retrySince = millis();
        Serial.println("[HANDSHAKE] HMAC valido; publica ECDH validada; esperando READY.");
        showPacket(wire); if (!result.reply.empty()) showPacket(result.reply);
    }
    if (result.event == Event::Established) {
        Serial.println("[SESSION OK] ECDH autenticado + HKDF + READY GCM. Puedes escribir texto.");
        Serial.printf("HANDSHAKE_MS,%lu\n", (unsigned long)(millis()-handshakeSince));
        handshakeSince = 0;
    }
    if (result.event == Event::Ack) {
        ++rxCount;
        TextRttResult timing;
        bool confirmed = textRtt.Confirm(result.acknowledgedSequence, verifiedAt, timing);
        metric("ACK_RX", 4, wire.size(), 0, elapsed, 0);
        if (confirmed) {
            lastConfirmedText = pendingTextWire; pendingTextWire.clear();
            metric("RTT_TEXT", timing.textBytes, timing.packetBytes, 0, 0, timing.elapsedUs);
            Serial.printf("[CONFIRMADO] Texto SEQ=%lu: receptor verifico y descifro; ACK cifrado verificado. RTT=%lu us (%lu.%03lu ms).\n",
                (unsigned long)timing.sequence, (unsigned long)timing.elapsedUs,
                (unsigned long)(timing.elapsedUs/1000), (unsigned long)(timing.elapsedUs%1000));
        } else Serial.println("[ACK] Referencia sin texto pendiente o fuera de plazo; no se registra RTT.");
        return;
    }
    if (result.event == Event::Text || result.event == Event::Ping || result.event == Event::Pong) {
        // El ACK se encola antes de imprimir. RX termina antes de preparar el ACK.
        // El receptor solo confirma despues de GCM y del control replay.
        if (result.event == Event::Text) {
            Bytes ack; uint32_t ackStart = micros();
            bool generated = session->Acknowledge(ack);
            uint32_t ackEncryptUs = micros()-ackStart;
            if (generated && wireless.Send(mac, ack)) {
                ++txCount; metric("ACK_TX", 4, ack.size(), ackEncryptUs, 0, 0);
            } else Serial.println("[ERROR] Texto aceptado, pero no se pudo encolar su ACK.");
        }
        ++rxCount;
        const char *direction = result.event == Event::Text ? "RX" : result.event == Event::Ping ? "PING_RX" : "PONG_RX";
        metric(direction, result.plaintext.size(), wire.size(), 0, elapsed, 0);
        if (result.event == Event::Text) {
            showPacket(wire); Serial.print("[SUCCESS] Verificado y descifrado: ");
            Serial.write(result.plaintext.data(), result.plaintext.size()); Serial.println();
        } else if (result.event == Event::Ping) sendProtected(PacketType::Pong, result.plaintext);
        else if (CryptoManager::Equal(pendingPing, result.plaintext)) {
            if (TextRtt::WithinDeadline(pingSince, verifiedAt)) metric("RTT", 0, 0, 0, 0, verifiedAt-pingSince);
            else Serial.println("[TIMEOUT] PONG fuera de plazo; no se registra RTT.");
            pendingPing.clear();
        }
    }
}
void setup() {
    Serial.begin(115200); delay(500);
    if (!wireless.Initialize()) { Serial.println("[FATAL] No se pudo inicializar ESP-NOW/cola."); return; }
    Mac mac{}; WiFi.macAddress(mac.data());
    std::array<uint8_t,32> key{};
#ifdef DEVICE_ROGUE
    Bytes randomKey = CryptoManager::Random(32);
    if (randomKey.size() != 32) { Serial.println("[FATAL] RNG."); return; }
    std::copy(randomKey.begin(), randomKey.end(), key.begin()); CryptoManager::Erase(randomKey);
    Serial.println("[INTRUSO] Sin credencial de la pareja: HELLO debe ser rechazado por B.");
#else
    std::copy(kPairSecret, kPairSecret+32, key.begin());
#endif
    session.reset(new Session(DEVICE_ROLE, mac, key));
    mbedtls_platform_zeroize(key.data(), key.size());
    Serial.printf("[BOOT] ESP-NOW v2; rol=%c; canal=1; MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
        DEVICE_ROLE == 1 ? 'A' : 'B', mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    metricHeader();
    help();
}
void loop() {
    readKeyboard();
    if (!session) { delay(20); return; }
    Mac source; Bytes wire;
    for (int i = 0; i < 4 && wireless.Read(source, wire); ++i) receive(source, wire);
    State state = session->Status();
    if (state == State::WaitResponse || state == State::WaitReady) {
        if (millis()-handshakeSince > 15000) {
            session->Reset(); handshakeSince = 0; Serial.println("[TIMEOUT] Intercambio incompleto; connect en A para reintentar.");
        } else if (millis()-retrySince >= 1000) {
            Bytes retry = session->Retry();
            Mac destination = state == State::WaitResponse ? broadcast : session->Peer();
            if (!retry.empty()) wireless.Send(destination, retry);
            retrySince = millis();
        }
    }
    if (!pendingPing.empty() && micros()-pingSince > 5000000) {
        pendingPing.clear(); Serial.println("[TIMEOUT] Ping sin respuesta en 5 s.");
    }
    if (textRtt.Expired(micros())) {
        textRtt.Clear(); pendingTextWire.clear();
        Serial.println("[TIMEOUT] Texto sin ACK valido en 5 s; recepcion no confirmada. No se calcula RTT.");
    }
    delay(2);
}
