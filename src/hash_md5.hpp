#pragma once

#include <vector>
#include <string>
#include <array>
#include <format>
#include <concepts>
#include <sstream>
#include <span>
#include <bit>
#include "crypt_concept.hpp"


template <typename T>
auto make_md5_hasher_initial_state(){
	// MD5 标准魔法数 (Magic Numbers)
	return std::to_array<T>({
			T{0x67452301U},
			T{0xEFCDAB89U},
			T{0x98BADCFEU},
			T{0x10325476U},
		});
}

/**
 * @brief 通用 MD5 实现类
 * @tparam T 内部运算使用的数值类型
 */
template <crypto_integer T = std::uint32_t>
class md5_hasher {
public:
    md5_hasher() = default;

    void reset() noexcept {
    	state_ = make_md5_hasher_initial_state<T>();
        buffer_.clear();
        total_bits_ = 0;
    }

    void update(std::span<const std::uint8_t> data) {
        total_bits_ += (data.size() * 8);
        
        buffer_.insert(buffer_.end(), data.begin(), data.end());

        while (buffer_.size() >= 64) {
            process_block(buffer_.data());
            buffer_.erase(buffer_.begin(), buffer_.begin() + 64);
        }
    }

    void update(std::string_view str) {
        update(std::span(reinterpret_cast<const std::uint8_t*>(str.data()), str.size()));
    }

    std::string finalize(){
        // 1. 填充 Padding
        // 追加一个 '1' bit (0x80)
        buffer_.push_back(0x80);

        // 填充 '0' 直到长度 % 64 == 56
        while ((buffer_.size() % 64) != 56) {
            buffer_.push_back({});
        }

        // 2. 追加 64 位的原始长度 (Little Endian)
        std::uint64_t saved_len = total_bits_;
        for (int i = 0; i < 8; ++i) {
            buffer_.push_back(static_cast<std::uint8_t>(saved_len & 0xFF));
            saved_len >>= 8;
        }

        // 3. 处理剩下的块
        // 此时 buffer 大小一定是 64 的倍数
        for (std::size_t i = 0; i < buffer_.size(); i += 64) {
            process_block(buffer_.data() + i);
        }

        // 4. 生成结果字符串 (Little Endian)
        std::stringstream result{};
        for (const auto& val : state_) {
            const auto v = static_cast<std::uint32_t>(val & (~0U));
            for (int i = 0; i < 4; ++i) {
                result << std::format("{:02x}", (v >> (i * 8)) & 0xFF);
            }
        }
        
        // 清理
        buffer_.clear();
        return std::move(result).str();
    }

private:
	// A, B, C, D
    std::array<T, 4> state_{make_md5_hasher_initial_state<T>()};

	// 待处理的数据流
    std::vector<std::uint8_t> buffer_{};

	// 原始消息总比特数
    std::uint64_t total_bits_{};

    // 32位 掩码常量 (用于确保 T 为大数类型时模拟 32 位溢出)
    static constexpr std::uint32_t mask_32 = ~0U;

    // F, G, H, I (非线性代换)
    // 利用位运算实现每一轮不同的逻辑混淆
    static T func_f(const T& x, const T& y, const T& z) noexcept { return (x & y) | ((~x) & z); }
    static T func_g(const T& x, const T& y, const T& z) noexcept { return (x & z) | (y & (~z)); }
    static T func_h(const T& x, const T& y, const T& z) noexcept { return x ^ y ^ z; }
    static T func_i(const T& x, const T& y, const T& z) noexcept { return y ^ (x | (~z)); }

    static T rotate_left(T x, int n) noexcept {
    	if constexpr (std::same_as<T, std::uint32_t>) {
    		return std::rotl(x, n);
    	}else{
    		x = x & mask_32;
    		return ((x << n) | (x >> (32 - n))) & mask_32;
    	}

    }

    // 核心变换函数
    void process_block(const std::uint8_t* block) noexcept {
        T a = state_[0];
        T b = state_[1];
        T c = state_[2];
        T d = state_[3];
        
        std::array<T, 16> x /*INTENDED INDETERMINATE*/;

        // 解码 64 字节块为 16 个 32 位字 (Little Endian)
        for (int i = 0; i < 16; ++i) {
            std::uint32_t temp = 0;
            temp |= static_cast<std::uint32_t>(block[i * 4 + 0]) << 0;
            temp |= static_cast<std::uint32_t>(block[i * 4 + 1]) << 8;
            temp |= static_cast<std::uint32_t>(block[i * 4 + 2]) << 16;
            temp |= static_cast<std::uint32_t>(block[i * 4 + 3]) << 24;
            x[i] = static_cast<T>(temp);
        }

        // MD5 的 64 步迭代
        auto step = [&]<typename Fn>(
        	Fn func,
        	T& dst, T src1, T src2, T src3, T input,
        	int shift, std::uint32_t constant) noexcept {
            T temp = func(src1, src2, src3);
            temp = (temp + src1) & mask_32;
            // dst = b + ((a + F(b,c,d) + x[k] + T[i]) << s)
            
            // temp = a + func(b, c, d) + input + constant
            T sum = dst + func(src1, src2, src3) + input + static_cast<T>(constant);
            sum = sum & mask_32; // 模拟溢出
            
            dst = (src1 + md5_hasher::rotate_left(sum, shift)) & mask_32;
        };

        // Round 1
        // [ABCD  0  7  1]  a = b + ((a + F(b,c,d) + X[ 0] + T[ 1]) <<< 7)
        step(func_f, a, b, c, d, x[0], 7, 0xd76aa478);
        step(func_f, d, a, b, c, x[1], 12, 0xe8c7b756);
        step(func_f, c, d, a, b, x[2], 17, 0x242070db);
        step(func_f, b, c, d, a, x[3], 22, 0xc1bdceee);
        step(func_f, a, b, c, d, x[4], 7, 0xf57c0faf);
        step(func_f, d, a, b, c, x[5], 12, 0x4787c62a);
        step(func_f, c, d, a, b, x[6], 17, 0xa8304613);
        step(func_f, b, c, d, a, x[7], 22, 0xfd469501);
        step(func_f, a, b, c, d, x[8], 7, 0x698098d8);
        step(func_f, d, a, b, c, x[9], 12, 0x8b44f7af);
        step(func_f, c, d, a, b, x[10], 17, 0xffff5bb1);
        step(func_f, b, c, d, a, x[11], 22, 0x895cd7be);
        step(func_f, a, b, c, d, x[12], 7, 0x6b901122);
        step(func_f, d, a, b, c, x[13], 12, 0xfd987193);
        step(func_f, c, d, a, b, x[14], 17, 0xa679438e);
        step(func_f, b, c, d, a, x[15], 22, 0x49b40821);

        // Round 2
        step(func_g, a, b, c, d, x[1], 5, 0xf61e2562);
        step(func_g, d, a, b, c, x[6], 9, 0xc040b340);
        step(func_g, c, d, a, b, x[11], 14, 0x265e5a51);
        step(func_g, b, c, d, a, x[0], 20, 0xe9b6c7aa);
        step(func_g, a, b, c, d, x[5], 5, 0xd62f105d);
        step(func_g, d, a, b, c, x[10], 9, 0x02441453);
        step(func_g, c, d, a, b, x[15], 14, 0xd8a1e681);
        step(func_g, b, c, d, a, x[4], 20, 0xe7d3fbc8);
        step(func_g, a, b, c, d, x[9], 5, 0x21e1cde6);
        step(func_g, d, a, b, c, x[14], 9, 0xc33707d6);
        step(func_g, c, d, a, b, x[3], 14, 0xf4d50d87);
        step(func_g, b, c, d, a, x[8], 20, 0x455a14ed);
        step(func_g, a, b, c, d, x[13], 5, 0xa9e3e905);
        step(func_g, d, a, b, c, x[2], 9, 0xfcefa3f8);
        step(func_g, c, d, a, b, x[7], 14, 0x676f02d9);
        step(func_g, b, c, d, a, x[12], 20, 0x8d2a4c8a);

        // Round 3
        step(func_h, a, b, c, d, x[5], 4, 0xfffa3942);
        step(func_h, d, a, b, c, x[8], 11, 0x8771f681);
        step(func_h, c, d, a, b, x[11], 16, 0x6d9d6122);
        step(func_h, b, c, d, a, x[14], 23, 0xfde5380c);
        step(func_h, a, b, c, d, x[1], 4, 0xa4beea44);
        step(func_h, d, a, b, c, x[4], 11, 0x4bdecfa9);
        step(func_h, c, d, a, b, x[7], 16, 0xf6bb4b60);
        step(func_h, b, c, d, a, x[10], 23, 0xbebfbc70);
        step(func_h, a, b, c, d, x[13], 4, 0x289b7ec6);
        step(func_h, d, a, b, c, x[0], 11, 0xeaa127fa);
        step(func_h, c, d, a, b, x[3], 16, 0xd4ef3085);
        step(func_h, b, c, d, a, x[6], 23, 0x04881d05);
        step(func_h, a, b, c, d, x[9], 4, 0xd9d4d039);
        step(func_h, d, a, b, c, x[12], 11, 0xe6db99e5);
        step(func_h, c, d, a, b, x[15], 16, 0x1fa27cf8);
        step(func_h, b, c, d, a, x[2], 23, 0xc4ac5665);

        // Round 4
        step(func_i, a, b, c, d, x[0], 6, 0xf4292244);
        step(func_i, d, a, b, c, x[7], 10, 0x432aff97);
        step(func_i, c, d, a, b, x[14], 15, 0xab9423a7);
        step(func_i, b, c, d, a, x[5], 21, 0xfc93a039);
        step(func_i, a, b, c, d, x[12], 6, 0x655b59c3);
        step(func_i, d, a, b, c, x[3], 10, 0x8f0ccc92);
        step(func_i, c, d, a, b, x[10], 15, 0xffeff47d);
        step(func_i, b, c, d, a, x[1], 21, 0x85845dd1);
        step(func_i, a, b, c, d, x[8], 6, 0x6fa87e4f);
        step(func_i, d, a, b, c, x[15], 10, 0xfe2ce6e0);
        step(func_i, c, d, a, b, x[6], 15, 0xa3014314);
        step(func_i, b, c, d, a, x[13], 21, 0x4e0811a1);
        step(func_i, a, b, c, d, x[4], 6, 0xf7537e82);
        step(func_i, d, a, b, c, x[11], 10, 0xbd3af235);
        step(func_i, c, d, a, b, x[2], 15, 0x2ad7d2bb);
        step(func_i, b, c, d, a, x[9], 21, 0xeb86d391);

        // 更新状态
        state_[0] = (state_[0] + a) & mask_32;
        state_[1] = (state_[1] + b) & mask_32;
        state_[2] = (state_[2] + c) & mask_32;
        state_[3] = (state_[3] + d) & mask_32;
    }
};
