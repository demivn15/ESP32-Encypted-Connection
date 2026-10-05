#include "support.h"
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include "text_rtt.h"

int main() {
    unsigned passed = 0;
    auto test = [&](const char *name, const std::function<void()> &run) {
        run(); ++passed; std::cout << "[OK] " << name << "\n";
    };
    try {
        test("sin clave fija: rechaza texto antes de READY", [] {
            Pair p; Bytes out; require(!p.a.Send(PacketType::Text,bytes("hola"),out) && out.empty(),"Fallback activo");
        });
        test("ECDH P-256: ambos secretos coinciden", [] {
            CryptoManager a,b; Bytes ap,bp,az,bz;
            require(a.Generate(ap) && b.Generate(bp) && a.Shared(bp,az) && b.Shared(ap,bz),"ECDH");
            require(az.size()==32 && CryptoManager::Equal(az,bz),"Secretos distintos");
            CryptoManager::Erase(az); CryptoManager::Erase(bz);
        });
        test("ECDH: publica invalida rechazada", [] {
            CryptoManager c; Bytes pub, secret; require(c.Generate(pub),"Generar");
            require(!c.Shared(Bytes(65,0),secret) && secret.empty(),"Punto invalido aceptado");
        });
        test("HKDF: vector RFC5869 caso 1", [] {
            Bytes ikm(22,0x0b), salt, info, output(42);
            for (int i=0;i<=12;++i) salt.push_back(uint8_t(i));
            for (int i=0xf0;i<=0xf9;++i) info.push_back(uint8_t(i));
            const uint8_t expected[] = {0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65};
            require(!mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),salt.data(),salt.size(),
                ikm.data(),ikm.size(),info.data(),info.size(),output.data(),output.size()) &&
                output==Bytes(expected,expected+42),"HKDF vector");
        });
        test("GCM: vector AES-128 cero NIST", [] {
            uint8_t key[16]={}; std::array<uint8_t,12> nonce{}; Bytes c,t,plain(16,0);
            const uint8_t ce[]={0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
            const uint8_t te[]={0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
            require(CryptoManager::Encrypt(key,nonce,{},plain,c,t) && c==Bytes(ce,ce+16) && t==Bytes(te,te+16),"GCM vector");
        });
        test("handshake autenticado y mensajes en ambos sentidos", [] {
            Pair p; p.Connect(); Bytes w;
            require(p.a.Send(PacketType::Text,bytes("hola"),w),"Enviar A"); auto r=p.b.Receive(macA,w);
            require(r.event==Event::Text && r.plaintext==bytes("hola"),"Texto B");
            require(p.b.Send(PacketType::Text,bytes("respuesta"),w),"Enviar B"); r=p.a.Receive(macB,w);
            require(r.event==Event::Text && r.plaintext==bytes("respuesta"),"Texto A");
        });
        test("intruso: HELLO con credencial falsa rechazado", [] {
            Session x(1,macX,testKey(0xee)), b(2,macB,testKey()); Bytes h; require(x.Start(h),"Intruso inicia");
            rejected(b.Receive(macX,h)); require(b.Status()==State::Idle,"Intruso altero estado");
        });
        test("HELLO alterado rechazado", [] {
            Pair p; require(p.a.Start(p.hello),"Start"); p.hello[45+10]^=1;
            rejected(p.b.Receive(macA,p.hello)); require(p.b.Status()==State::Idle,"Estado");
        });
        test("respuesta ECDH alterada rechazada", [] {
            Pair p; require(p.a.Start(p.hello),"Start"); auto r=p.b.Receive(macA,p.hello);
            require(r.event==Event::Handshake,"Hello"); r.reply[45+20]^=1; rejected(p.a.Receive(macB,r.reply));
        });
        test("respuesta con SID de otra sesion rechazada", [] {
            Pair p,q; require(p.a.Start(p.hello) && q.a.Start(q.hello),"Start");
            auto r=q.b.Receive(macA,q.hello); rejected(p.a.Receive(macB,r.reply));
        });
        test("READY alterado no confirma sesion", [] {
            Pair p; require(p.a.Start(p.hello),"Start"); auto r=p.b.Receive(macA,p.hello);
            r=p.a.Receive(macB,r.reply); r.reply.back()^=1; rejected(p.b.Receive(macA,r.reply));
            require(p.b.Status()==State::WaitReady,"Confirmo sin prueba");
        });
        test("perdida HELLO/READY: reintentos no regeneran claves", [] {
            Pair p; require(p.a.Start(p.hello) && p.a.Retry()==p.hello,"Retry A");
            auto r=p.b.Receive(macA,p.hello); Bytes response=r.reply;
            r=p.b.Receive(macA,p.hello); require(r.event==Event::Duplicate && r.reply==response,"Retry B");
            r=p.a.Receive(macB,response); Bytes ready=r.reply; require(p.a.Retry()==ready,"Retry READY");
            r=p.b.Receive(macA,ready); Bytes ack=r.reply;
            r=p.b.Receive(macA,ready); require(r.event==Event::Duplicate && r.reply==ack,"ACK perdido");
            r=p.a.Receive(macB,ack); require(r.event==Event::Established,"Ready A");
            r=p.a.Receive(macB,ack); require(r.event==Event::Duplicate && r.reply.empty(),"Sin bucle ACK");
        });
        test("ciphertext alterado rechazado; registro original aun valido", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.payload[0]^=1;})));
            require(p.b.Receive(macA,w).plaintext==bytes("hola"),"Contador consumido antes de GCM");
        });
        test("tag alterado rechazado", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.tag[0]^=1;})));
        });
        test("forjado con ID SID SEQ validos rechazado", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.payload.assign(x.payload.size(),0xa7);x.tag.assign(16,0);})));
        });
        test("replay: texto se entrega una sola vez", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("replay"),w),"Send");
            require(p.b.Receive(macA,w).event==Event::Text,"Primer mensaje"); rejected(p.b.Receive(macA,w));
        });
        test("contador forjado no envenena ventana", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.sequence=1000000;
                for(int i=0;i<4;++i)x.nonce[11-i]=uint8_t(x.sequence>>(8*i));})));
            require(p.b.Receive(macA,w).event==Event::Text,"Ventana envenenada");
        });
        test("MAC declarada y origen real deben coincidir", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macX,w)); rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.sender[0]^=1;})));
        });
        test("tipo rol SID y nonce alterados rechazados", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("12345678"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.type=PacketType::Ping;})));
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.role=2;})));
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.sid[0]^=1;})));
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.nonce[0]^=1;})));
        });
        test("reflexion de un mensaje al mismo emisor rechazada", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.a.Receive(macB,w)); rejected(p.a.Receive(macA,w));
        });
        test("clave/nonce por direccion: mismo texto produce otro cifrado", [] {
            Pair p; p.Connect(); Bytes aw,bw; SecurePacket ap,bp;
            require(p.a.Send(PacketType::Text,bytes("hola"),aw) && p.b.Send(PacketType::Text,bytes("hola"),bw),"Send");
            require(PacketHandler::Deserialize(aw,ap) && PacketHandler::Deserialize(bw,bp),"Parse");
            require(ap.payload!=bp.payload,"Ciphertext identico por direccion");
        });
        test("misma direccion: SEQ y cifrado cambian para texto repetido", [] {
            Pair p; p.Connect(); Bytes a,b; SecurePacket x,y;
            require(p.a.Send(PacketType::Text,bytes("hola"),a) && p.a.Send(PacketType::Text,bytes("hola"),b),"Send");
            require(PacketHandler::Deserialize(a,x) && PacketHandler::Deserialize(b,y) &&
                    x.sequence!=y.sequence && x.nonce!=y.nonce && x.payload!=y.payload,"Reutilizacion");
        });
        test("nueva sesion: SID distinto y mensaje viejo rechazado", [] {
            Pair p; p.Connect(); Bytes old; require(p.a.Send(PacketType::Text,bytes("viejo"),old),"Send");
            Bytes oldHello=p.hello; p.a.Reset(); p.b.Reset(); p.Connect();
            require(p.hello!=oldHello,"Sesion repetida"); rejected(p.b.Receive(macA,old));
        });
        test("sesion activa no reemplazable por HELLO repetido", [] {
            Pair p; p.Connect(); rejected(p.b.Receive(macA,p.hello));
            require(p.b.Status()==State::Established,"Reinicio remoto");
        });
        test("ventana replay permite desorden pero rechaza duplicados/antiguos", [] {
            ReplayProtection r; require(r.ValidateAndUpdate(0) && r.ValidateAndUpdate(3) && r.ValidateAndUpdate(1),"Desorden");
            require(!r.ValidateAndUpdate(1),"Duplicate");
            require(r.ValidateAndUpdate(UINT32_MAX) && !r.ValidateAndUpdate(2),"Overflow signed");
        });
        test("texto vacio 128 bytes UTF8 y rechazo de 129 bytes", [] {
            Pair p; p.Connect(); Bytes w;
            for (Bytes text : {Bytes{}, Bytes(128,'x'), bytes("acentos: \xc3\xa1 \xc3\xb1")}) {
                require(p.a.Send(PacketType::Text,text,w),"Send"); auto r=p.b.Receive(macA,w);
                require(r.event==Event::Text && r.plaintext==text,"Bytes exactos");
            }
            require(!p.a.Send(PacketType::Text,Bytes(129,'x'),w) && w.empty(),"Overflow");
        });
        test("parser rechaza truncados sobrantes tipo longitud y version", [] {
            Pair p; p.Connect(); Bytes w; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            SecurePacket x;
            for(size_t n=0;n<w.size();++n) require(!PacketHandler::Deserialize(Bytes(w.begin(),w.begin()+n),x),"Truncado");
            Bytes b=w; b.push_back(0); require(!PacketHandler::Deserialize(b,x),"Sobrante");
            b=w;b[3]=0xff;require(!PacketHandler::Deserialize(b,x),"Tipo");
            b=w;b[31]=0xff;require(!PacketHandler::Deserialize(b,x),"Longitud");
            b=w;b[2]=1;require(!PacketHandler::Deserialize(b,x),"Version");
        });
        test("ping y pong protegidos", [] {
            Pair p; p.Connect(); Bytes w,token(8,0x32);
            require(p.a.Send(PacketType::Ping,token,w),"Ping"); auto r=p.b.Receive(macA,w);
            require(r.event==Event::Ping && r.plaintext==token,"Ping RX");
            require(p.b.Send(PacketType::Pong,r.plaintext,w),"Pong");r=p.a.Receive(macB,w);
            require(r.event==Event::Pong && r.plaintext==token,"Pong RX");
        });
        test("alterar cualquier bit de un registro impide entregar texto", [] {
            Pair p; p.Connect(); Bytes original;
            require(p.a.Send(PacketType::Text,bytes("completo"),original),"Send");
            for(size_t i=0;i<original.size();++i) for(unsigned bit=0;bit<8;++bit) {
                Bytes changed=original;changed[i]^=uint8_t(1u<<bit);
                rejected(p.b.Receive(macA,changed));
            }
            require(p.b.Receive(macA,original).event==Event::Text,"Cambio estado tras rechazos");
        });
        test("parser de 10000 entradas aleatorias mantiene limites", [] {
            for(unsigned i=0;i<10000;++i) {
                Bytes raw=CryptoManager::Random(i%300);SecurePacket packet;
                if(PacketHandler::Deserialize(raw,packet)) {
                    Bytes canonical;require(PacketHandler::Serialize(packet,canonical) && canonical==raw,"Canonical");
                }
            }
        });
        test("ACK solo despues de TEXT verificado y una sola vez", [] {
            Pair p; p.Connect(); Bytes text,ack;
            require(!p.b.Acknowledge(ack) && ack.empty(),"ACK prematuro");
            require(p.a.Send(PacketType::Text,bytes("hola"),text),"Texto");
            auto received=p.b.Receive(macA,text);
            require(received.event==Event::Text && received.sequence>0,"Receive");
            require(p.b.Acknowledge(ack),"ACK");
            auto result=p.a.Receive(macB,ack);
            require(result.event==Event::Ack && result.acknowledgedSequence==received.sequence && result.plaintext.empty(),"Referencia ACK");
            require(!p.b.Acknowledge(ack) && ack.empty(),"ACK duplicado");
        });
        test("ACK funciona para textos simultaneos en ambas direcciones", [] {
            Pair p; p.Connect(); Bytes a,b,aa,ba;
            require(p.a.Send(PacketType::Text,bytes("A"),a) && p.b.Send(PacketType::Text,bytes("B"),b),"Enviar");
            auto ar=p.b.Receive(macA,a), br=p.a.Receive(macB,b);
            require(ar.event==Event::Text && br.event==Event::Text && p.b.Acknowledge(ba) && p.a.Acknowledge(aa),"ACKs");
            auto ab=p.a.Receive(macB,ba), bb=p.b.Receive(macA,aa);
            require(ab.event==Event::Ack && bb.event==Event::Ack && ab.acknowledgedSequence==ar.sequence && bb.acknowledgedSequence==br.sequence,"Direccion");
        });
        test("TEXT alterado no habilita ACK", [] {
            Pair p; p.Connect(); Bytes w,ack; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            rejected(p.b.Receive(macA,alter(w,[](SecurePacket &x){x.tag[0]^=1;})));
            require(!p.b.Acknowledge(ack),"Confirmo texto invalido");
        });
        test("TEXT replay no entrega otra vez ni genera otro ACK", [] {
            Pair p; p.Connect(); Bytes w,ack; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            require(p.b.Receive(macA,w).event==Event::Text && p.b.Acknowledge(ack),"ACK inicial");
            rejected(p.b.Receive(macA,w)); require(!p.b.Acknowledge(ack),"ACK replay");
        });
        test("ACK alterado rechazado y original todavia aceptado", [] {
            Pair p; p.Connect(); Bytes w,ack; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            require(p.b.Receive(macA,w).event==Event::Text && p.b.Acknowledge(ack),"ACK");
            rejected(p.a.Receive(macB,alter(ack,[](SecurePacket &x){x.payload[0]^=1;})));
            rejected(p.a.Receive(macB,alter(ack,[](SecurePacket &x){x.tag[0]^=1;})));
            require(p.a.Receive(macB,ack).event==Event::Ack,"ACK original"); rejected(p.a.Receive(macB,ack));
        });
        test("ACK anterior a reset no confirma otra sesion", [] {
            Pair p; p.Connect(); Bytes w,ack; require(p.a.Send(PacketType::Text,bytes("hola"),w),"Send");
            require(p.b.Receive(macA,w).event==Event::Text && p.b.Acknowledge(ack),"ACK");
            p.a.Reset(); p.b.Reset(); p.Connect(); rejected(p.a.Receive(macB,ack)); require(!p.b.Acknowledge(w),"ACK retenido al reset");
        });
        test("ACK tiene 4 bytes protegidos y longitud exacta", [] {
            SecurePacket p; p.type=PacketType::Ack; p.role=1; p.sequence=1; p.payload=Bytes(4,0); p.tag=Bytes(16,0);
            Bytes w; require(PacketHandler::Serialize(p,w) && w.size()==65,"ACK forma");
            p.payload.resize(3); require(!PacketHandler::Serialize(p,w),"ACK corto");
            p.payload.resize(5); require(!PacketHandler::Serialize(p,w),"ACK largo");
        });
        test("RTT corresponde a SEQ exacta y no mezcla pendientes", [] {
            TextRtt timer; TextRttResult r;
            require(timer.Start(5,100,16,77) && !timer.Start(6,200,16,77),"Pendientes");
            require(!timer.Confirm(4,400,r) && timer.Pending(),"Referencia incorrecta");
            require(timer.Confirm(5,1000,r) && r.elapsedUs==900 && r.textBytes==16 && r.packetBytes==77 && !timer.Pending(),"RTT");
            require(!timer.Confirm(5,1100,r),"Dos medidas de mismo ACK");
        });
        test("RTT no registra confirmacion tardia y reinicio cancela", [] {
            TextRtt timer; TextRttResult r;
            require(timer.Start(7,100,5,66) && timer.Expired(5000100),"Timeout");
            require(!timer.Confirm(7,5000100,r),"RTT tardio");
            timer.Clear(); require(!timer.Confirm(7,5000200,r),"ACK viejo");
            require(!timer.Start(0,0,5,66),"SEQ cero");
        });
        test("RTT calcula bien cuando micros desborda", [] {
            TextRtt timer; TextRttResult r;
            require(timer.Start(1,UINT32_MAX-99,0,61) && timer.Confirm(1,100,r) && r.elapsedUs==200,"Desbordamiento");
        });
        test("plazo de RTT compartido con ping: limite y rollover", [] {
            require(TextRtt::WithinDeadline(100,5000099),"Antes de 5 s");
            require(!TextRtt::WithinDeadline(100,5000100),"Acepto respuesta vencida");
            require(TextRtt::WithinDeadline(UINT32_MAX-99,100),"Rollover");
        });
        std::cout << passed << " pruebas aprobadas. No se ha probado radio/hardware.\n";
        return 0;
    } catch (const std::exception &e) { std::cerr << "[ERROR] " << e.what() << "\n"; return 1; }
}
