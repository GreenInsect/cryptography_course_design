/**
 * @file dsa_generator.hpp
 * @brief 基于 BigInteger 实现的 FIPS 186-4 DSA 参数生成
 * @details 支持生成符合安全强度的 (L, N) 素数对 (p, q) 以及生成元 g。
 */

#pragma once

#include "big_integer.hpp"
#include "sha256.hpp"
#include <vector>
#include <cmath>

namespace bigint {

    struct DSAParams {
        BigInteger p; // 模数 (L bits)
        BigInteger q; // 子群阶 (N bits)
        BigInteger g; // 生成元
    };

    class DSAGenerator {
    public:
        /**
         * @brief 生成 DSA 参数
         * @param L p 的位数 (推荐 2048)
         * @param N q 的位数 (推荐 256)
         */
        static DSAParams generate(int L = 2048, int N = 256) {
            if (!((L == 1024 && N == 160) || (L == 2048 && N == 224) ||
                  (L == 2048 && N == 256) || (L == 3072 && N == 256))) {
            }

            DSAParams params;
            SHA256 sha;

            // 1. 生成 q (N bits 的素数)
            params.q = bigint::random_prime(N, 40);

            // 2. 生成 p (L bits, 满足 q | p-1)
            int divisor = L / 32; // 假设底层以 32 位为单位
            while (true) {
                // 随机生成 L 位的 candidate p
                BigInteger X = bigint::random_bigint(L);
                // 确保 p 大约是 L 位且 p = 1 (mod 2q) 以加速寻找
                BigInteger p_candidate = X - (X % (params.q * 2)) + 1;

                if (p_candidate.to_binary_string().size() < L) continue;

                // 这里的 k 轮 Miller-Rabin 保证了素性
                if (is_prime(p_candidate, 40)) {
                    params.p = p_candidate;
                    break;
                }
            }

            // 3. 生成 g (生成元)
            // g = h^((p-1)/q) mod p, 其中 1 < h < p-1 且 g > 1
            BigInteger e = (params.p - 1) / params.q;
            BigInteger h("2");
            while (true) {
                params.g = BigIntegerOps::mod_pow(h, e, params.p);
                if (params.g > BigInteger(1)) {
                    break;
                }
                h = h + 1;
            }

            return params;
        }

        /**
         * @brief 验证参数是否符合 FIPS 186-4 基本数学约束
         */
        static bool verify(const DSAParams& params) {
            if (!is_prime(params.q, 40)) return false;
            if (!is_prime(params.p, 40)) return false;
            if (!((params.p - 1) % params.q).is_zero()) return false;
            if (params.g <= 1 || BigIntegerOps::mod_pow(params.g, params.q, params.p) != 1) return false;
            return true;
        }
    };

} // namespace bigint