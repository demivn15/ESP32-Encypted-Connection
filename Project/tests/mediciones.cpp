#include "support.h"
#include <chrono>
#include <fstream>
#include <iomanip>
using Clock=std::chrono::steady_clock;
double us(Clock::time_point a,Clock::time_point b) {
    return std::chrono::duration<double,std::micro>(b-a).count();
}
int main(int argc,char **argv) {
    try {
        std::ofstream file(argc>1?argv[1]:"measurements/pc.csv"); require(bool(file),"Abrir CSV");
        Pair p; p.Connect();
        file<<"entorno,plaintext_bytes,packet_bytes,encrypt_us,verify_decrypt_us,echo_us\n"<<std::fixed<<std::setprecision(3);
        for(size_t size:{size_t(1),size_t(16),size_t(64),size_t(128)}) {
            for(int i=0;i<30;++i) {
                Bytes text(size,'x'),wire,reply; auto start=Clock::now();
                require(p.a.Send(PacketType::Text,text,wire),"Cifrar");auto encrypted=Clock::now();
                auto r=p.b.Receive(macA,wire);auto verified=Clock::now();
                require(r.event==Event::Text && r.plaintext==text,"Verificar");
                require(p.b.Send(PacketType::Text,r.plaintext,reply),"Eco");r=p.a.Receive(macB,reply);
                require(r.event==Event::Text && r.plaintext==text,"Eco RX");auto end=Clock::now();
                file<<"PC_memoria_sin_radio,"<<size<<','<<wire.size()<<','<<us(start,encrypted)<<','
                    <<us(encrypted,verified)<<','<<us(start,end)<<'\n';
            }
        }
        require(bool(file),"Guardar CSV");
        std::cout<<"120 muestras reales PC. echo_us NO es latencia WiFi; no incluye radio.\n";return 0;
    } catch(const std::exception &e) { std::cerr<<e.what()<<'\n';return 1; }
}
