#include "crypto_manager.h"
#include <fstream>
#include <iostream>
#include <iomanip>
int main() {
    std::ifstream existing("include/pair_secret.h");
    if(existing.good()) { std::cout<<"Se conserva la credencial existente.\n";return 0; }
    Bytes key=CryptoManager::Random(32);
    if(key.size()!=32) return 1;
    std::ofstream out("include/pair_secret.h");
    out<<"#pragma once\n#include <cstdint>\n// PRIVADO: misma credencial en A y B; no publicar.\nstatic const uint8_t kPairSecret[32] = {";
    for(size_t i=0;i<key.size();++i) out<<(i?",":"")<<"0x"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(key[i]);
    out<<"};\n";CryptoManager::Erase(key);
    if(!out.good()) return 1;
    std::cout<<"Credencial aleatoria creada. Compartir el mismo archivo solo con la pareja.\n";return 0;
}
