/**
 * @file sha256.hpp
 * @brief 基于 BigInteger 库实现的 SHA-256 算法
 * @details 实现了标准 SHA-256逻辑，支持处理 std::string 或 BigInteger 输入。
 */

#pragma once

#include "big_integer.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace bigint {

    class SHA256 {
    private:
        // SHA-256 初始哈希值 (前 8 个素数平方根的小数部分前 32 位)
        std::uint32_t state[8];

        // SHA-256 常量 K (前 64 个素数立方根的小数部分前 32 位)
        static constexpr std::uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // 辅助宏函数
        static inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) { return (x >> n) | (x << (32 - n)); }
        static inline std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (~x & z); }
        static inline std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
        static inline std::uint32_t sig0(std::uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
        static inline std::uint32_t sig1(std::uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
        static inline std::uint32_t SIG0(std::uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
        static inline std::uint32_t SIG1(std::uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

        void transform(const std::uint8_t* block) {
            std::uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
            }
            for (int i = 16; i < 64; ++i) {
                w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];
            }

            std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (int i = 0; i < 64; ++i) {
                std::uint32_t t1 = h + SIG1(e) + choose(e, f, g) + K[i] + w[i];
                std::uint32_t t2 = SIG0(a) + majority(a, b, c);
                h = g; g = f; f = e;
                e = d + t1;
                d = c; c = b; b = a;
                a = t1 + t2;
            }

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }

    public:
        SHA256() { reset(); }

        void reset() {
            state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
            state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        }

        /**
         * @brief 对字节序列进行 SHA-256 加密
         */
        std::vector<std::uint8_t> hash(const std::uint8_t* data, size_t length) {
            reset();
            std::vector<std::uint8_t> msg(data, data + length);
            std::uint64_t bit_len = length * 8;

            // 填充(padding)
            msg.push_back(0x80);
            while ((msg.size() + 8) % 64 != 0) msg.push_back(0x00);

            // 附加长度
            for (int i = 7; i >= 0; --i) {
                msg.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xFF));
            }

            // 处理每个 512-bit 分组
            for (size_t i = 0; i < msg.size(); i += 64) {
                transform(&msg[i]);
            }

            // 整理结果
            std::vector<std::uint8_t> result;
            for (int i = 0; i < 8; ++i) {
                result.push_back(static_cast<std::uint8_t>((state[i] >> 24) & 0xFF));
                result.push_back(static_cast<std::uint8_t>((state[i] >> 16) & 0xFF));
                result.push_back(static_cast<std::uint8_t>((state[i] >> 8) & 0xFF));
                result.push_back(static_cast<std::uint8_t>(state[i] & 0xFF));
            }
            return result;
        }

        /**
         * @brief 直接处理 BigInteger 并返回另一个 BigInteger
         */
        BigInteger hash(const BigInteger& bi) {
            std::vector<std::uint8_t> bytes = bi.to_bytes();
            std::vector<std::uint8_t> hashed_bytes = hash(bytes.data(), bytes.size());
            // 将结果转换回 BigInteger
            return BigInteger(std::span{hashed_bytes.data(), hashed_bytes.size()}, false);
        }

        /**
         * @brief 处理字符串并返回十六进制摘要
         */
        std::string hash_to_hex(const std::string& str) {
            std::vector<std::uint8_t> hashed = hash(reinterpret_cast<const std::uint8_t*>(str.data()), str.size());
            std::stringstream ss;
            for (auto b : hashed) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
            return ss.str();
        }
    };

} // namespace bigint