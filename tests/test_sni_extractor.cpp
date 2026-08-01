#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "../include/sni_extractor.h"
#include <vector>
#include <cstdint>

using namespace DPI;

// Helper to build a minimal valid TLS Client Hello containing a given SNI hostname
static std::vector<uint8_t> buildClientHello(const std::string& hostname) {
    std::vector<uint8_t> pkt;

    // --- SNI Extension (build this first so we know its length) ---
    std::vector<uint8_t> sni_ext;
    sni_ext.push_back(0x00); sni_ext.push_back(0x00);       // Extension Type = 0x0000 (SNI)
    uint16_t sni_list_len = 3 + hostname.size();             // type(1) + len(2) + hostname
    uint16_t ext_data_len = 2 + sni_list_len;                 // sni_list_len field(2) + list
    sni_ext.push_back((ext_data_len >> 8) & 0xFF);
    sni_ext.push_back(ext_data_len & 0xFF);                   // Extension Length
    sni_ext.push_back((sni_list_len >> 8) & 0xFF);
    sni_ext.push_back(sni_list_len & 0xFF);                   // SNI List Length
    sni_ext.push_back(0x00);                                  // SNI Type = hostname
    sni_ext.push_back((hostname.size() >> 8) & 0xFF);
    sni_ext.push_back(hostname.size() & 0xFF);                // SNI Length
    for (char c : hostname) sni_ext.push_back((uint8_t)c);    // SNI Value

    // --- Client Hello body ---
    std::vector<uint8_t> body;
    body.push_back(0x03); body.push_back(0x03);               // Client Version (TLS 1.2)
    for (int i = 0; i < 32; i++) body.push_back(0xAA);         // Random (32 bytes, dummy)
    body.push_back(0x00);                                      // Session ID Length = 0
    body.push_back(0x00); body.push_back(0x02);                // Cipher Suites Length = 2
    body.push_back(0x00); body.push_back(0x2F);                // 1 cipher suite (dummy)
    body.push_back(0x01);                                      // Compression Methods Length = 1
    body.push_back(0x00);                                      // Compression Method = null

    uint16_t extensions_len = sni_ext.size();
    body.push_back((extensions_len >> 8) & 0xFF);
    body.push_back(extensions_len & 0xFF);                     // Extensions Length
    for (auto b : sni_ext) body.push_back(b);                  // Extensions data

    // --- Handshake Header ---
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);                                 // Handshake Type = Client Hello
    uint32_t body_len = body.size();
    handshake.push_back((body_len >> 16) & 0xFF);
    handshake.push_back((body_len >> 8) & 0xFF);
    handshake.push_back(body_len & 0xFF);                       // 3-byte length
    for (auto b : body) handshake.push_back(b);

    // --- TLS Record Header ---
    pkt.push_back(0x16);                                        // Content Type = Handshake
    pkt.push_back(0x03); pkt.push_back(0x03);                   // Version = TLS 1.2
    uint16_t record_len = handshake.size();
    pkt.push_back((record_len >> 8) & 0xFF);
    pkt.push_back(record_len & 0xFF);                            // Record Length
    for (auto b : handshake) pkt.push_back(b);

    return pkt;
}

TEST_CASE("SNIExtractor correctly extracts hostname from valid Client Hello") {
    auto pkt = buildClientHello("example.com");
    auto result = SNIExtractor::extract(pkt.data(), pkt.size());

    CHECK(result.has_value());
    CHECK(result.value() == "example.com");
}

TEST_CASE("SNIExtractor returns nullopt for truncated packet") {
    auto pkt = buildClientHello("example.com");
    pkt.resize(pkt.size() / 2);  // Cut it in half — truncated

    auto result = SNIExtractor::extract(pkt.data(), pkt.size());
    CHECK_FALSE(result.has_value());
}

TEST_CASE("SNIExtractor returns nullopt for non-TLS garbage input") {
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04};
    auto result = SNIExtractor::extract(garbage.data(), garbage.size());
    CHECK_FALSE(result.has_value());
}

TEST_CASE("SNIExtractor handles empty payload without crashing") {
    std::vector<uint8_t> empty;
    auto result = SNIExtractor::extract(empty.data(), empty.size());
    CHECK_FALSE(result.has_value());
}

TEST_CASE("QUICSNIExtractor does not crash on short buffer near handshake byte") {
    // Regression test for the buffer-underflow bug we fixed:
    // payload[i] == 0x01 appearing near the start (i < 5) used to
    // compute payload + i - 5, reading before the buffer.
    std::vector<uint8_t> pkt = {0x80, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA};
    auto result = QUICSNIExtractor::extract(pkt.data(), pkt.size());
    CHECK_FALSE(result.has_value());  // Should safely return nullopt, not crash
}