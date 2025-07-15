/**
 * @file main.cpp
 * @brief SM4 ECB mode standard test vector
 */

#include "include/SM4.h"
#include <iostream>
#include <iomanip>

void dumpHex(const std::vector<uint8_t>& data) {
    for (uint8_t v : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(v) << ' ';
    std::cout << std::dec << '\n';
}

void testSM4Vector() {
    const std::vector<uint8_t> key = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    const std::vector<uint8_t> plain = {
            0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
            0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };

    SM4 sm4(key);
    auto cipher = sm4.encrypt(plain);
    auto back   = sm4.decrypt(cipher);

    std::cout << "===== Standard Test Vector =====\n";
    std::cout << "Plain : "; dumpHex(plain);
    std::cout << "Cipher: "; dumpHex(cipher);
    std::cout << "Dec   : "; dumpHex(back);
    std::cout << (plain == back ? "Result: SUCCESS" : "Result: FAILED") << '\n';
}

int main() {
    try {
        testSM4Vector();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}