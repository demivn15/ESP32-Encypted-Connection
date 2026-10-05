#pragma once
#include "session.h"
#include <stdexcept>
#include <functional>
#include <iostream>
inline void require(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
inline Bytes bytes(const std::string &s) { return Bytes(s.begin(),s.end()); }
inline std::array<uint8_t,32> testKey(uint8_t seed = 0x57) {
    std::array<uint8_t,32> key{}; key.fill(seed); return key; // Solo pruebas PC.
}
const Mac macA{{2,0,0,0,0,1}}, macB{{2,0,0,0,0,2}}, macX{{2,0,0,0,0,9}};
struct Pair {
    Session a, b;
    Bytes hello, response, readyA, readyB;
    Pair() : a(1,macA,testKey()), b(2,macB,testKey()) {}
    void Connect() {
        require(a.Start(hello), "HELLO");
        auto r = b.Receive(macA,hello); require(r.event == Event::Handshake, "RESP autenticada"); response = r.reply;
        r = a.Receive(macB,response); require(r.event == Event::Handshake, "ECDH A"); readyA = r.reply;
        r = b.Receive(macA,readyA); require(r.event == Event::Established, "READY B"); readyB = r.reply;
        r = a.Receive(macB,readyB); require(r.event == Event::Established, "READY A");
        require(a.Status()==State::Established && b.Status()==State::Established,"Sesion bidireccional");
    }
};
inline void rejected(const ReceiveResult &r) {
    require(r.event == Event::Rejected && r.plaintext.empty(), "Entrego texto de registro invalido");
}
inline Bytes alter(const Bytes &wire, const std::function<void(SecurePacket &)> &change) {
    SecurePacket p; Bytes out; require(PacketHandler::Deserialize(wire,p),"Leer fixture");
    change(p); require(PacketHandler::Serialize(p,out),"Serializar fixture"); return out;
}
