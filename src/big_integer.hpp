//Mainly Written By Huang Zhihui
//Modified By He Mingxun. mainly engineering optimizing e.g. support move construct and other util functions
//Text encoded in UTF-8

/**
 * @file bigint.hpp
 * @brief C++20 BigInteger Library
 * @details 任意精度整数运算库，支持基础运算、数论运算、位运算及随机数生成。
 * 完全支持像 scalar integer 一样的运算符重载。
 */

#pragma once

#include <iostream>
#include <vector>
#include <complex>
#include <algorithm>
#include <string>
#include <chrono>
#include <stdexcept>
#include <cctype>
#include <random>
#include <cstdint>
#include <cassert>
#include <numbers> // C++20
#include <compare> // C++20 for operator<=>
#include <optional>
#include <limits>
#include <span>


#include "crypt_concept.hpp"

#if defined(__GNUC__) || defined(__clang__)
	#define BIGINT_FORCE_INLINE [[gnu::always_inline]]
#elif defined(_MSC_VER)
	#define BIGINT_FORCE_INLINE [[msvc::force_inline]]
#else
	#define BIGINT_FORCE_INLINE
#endif

namespace bigint {

// 常量定义
constexpr inline uint32_t BASE = 256;
constexpr inline uint8_t BASE_BITS = 8;
constexpr inline std::string_view HEX_CHARS = "0123456789abcdef";

// 前向声明
struct DivisionResult;
struct ExtendedGcdResult;
class BigIntegerOps;

/**
 * @brief 大整数类
 */
class BigInteger {
    friend class BigIntegerOps;

private:
    std::vector<uint8_t> mag;  // 小端序存储绝对值
    bool sign;                 // false: 正, true: 负

    void remove_leading_zeros();
    void decimal_string_to_mag(std::string_view num_str);
    void binary_string_to_mag(std::string_view bin_str);
    void hex_string_to_mag(std::string_view hex_str);

public:
    // ----------------------------------------------------------------------
    // 构造函数
    // ----------------------------------------------------------------------
    BigInteger();
    BigInteger(std::string_view str);
    BigInteger(std::string_view str, int base);
    BigInteger(std::span<const std::uint8_t> bytes, bool is_negative = false);
    BigInteger(std::span<const std::byte> bytes, bool is_negative = false) : BigInteger(std::span{
	    reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()}, is_negative) {}
    BigInteger(const uint8_t* bytes, size_t length, bool is_negative = false);
    // 允许从基础整型隐式构造，以支持 scalar 混合运算 (e.g. bigint + 1)
    BigInteger(long long num); 
    BigInteger(unsigned long long num);
    BigInteger(int num) : BigInteger(static_cast<long long>(num)) {}
    BigInteger(unsigned int num) : BigInteger(static_cast<unsigned long long>(num)) {}

    // ----------------------------------------------------------------------
    // 类型转换与显式转换
    // ----------------------------------------------------------------------
    std::string to_string() const;
    std::string to_binary_string() const;
    std::string to_hex_string(bool uppercase = true) const;
    std::vector<uint8_t> to_bytes() const;

    // 支持 if (bigint) 检查是否非零
    explicit operator bool() const;

    // 强制转换为基础类型 (截断)
    explicit operator long long() const;

    // 安全转换为 long long (溢出抛出异常)
    BIGINT_FORCE_INLINE long long to_long_long_checked() const;

    // ----------------------------------------------------------------------
    // 基础状态查询
    // ----------------------------------------------------------------------
    BIGINT_FORCE_INLINE bool get_sign() const { return sign; }
    BIGINT_FORCE_INLINE void set_sign(bool s) { if (!is_zero()) sign = s; } // 0 始终为正
    BIGINT_FORCE_INLINE void set_bytes(const std::vector<uint8_t>& bytes);
    BIGINT_FORCE_INLINE bool is_zero() const;
    BIGINT_FORCE_INLINE void swap(BigInteger& other) noexcept;

    // 快速模取
    BIGINT_FORCE_INLINE uint8_t mod4() const;
    BIGINT_FORCE_INLINE uint8_t mod8() const;

    // ----------------------------------------------------------------------
    // 运算符重载 (Operator Overloading)
    // ----------------------------------------------------------------------

    // 1. 三路比较运算符 (C++20 spaceship) - 自动生成 ==, !=, <, <=, >, >=
    BIGINT_FORCE_INLINE std::strong_ordering operator<=>(const BigInteger& other) const;
    BIGINT_FORCE_INLINE bool operator==(const BigInteger& other) const; // 显式声明以优化性能

    // 2. 自增/自减
    BIGINT_FORCE_INLINE BigInteger& operator++();    // 前置 ++a
    BIGINT_FORCE_INLINE BigInteger operator++(int);  // 后置 a++
    BIGINT_FORCE_INLINE BigInteger& operator--();    // 前置 --a
    BIGINT_FORCE_INLINE BigInteger operator--(int);  // 后置 a--

    // 3. 一元运算符
    BIGINT_FORCE_INLINE BigInteger operator+() const; // +a
    BIGINT_FORCE_INLINE BigInteger operator-() const; // -a
    BIGINT_FORCE_INLINE BigInteger operator~() const; // ~a (按位取反)
    BIGINT_FORCE_INLINE bool operator!() const;       // !a (逻辑非)

    // 4. 复合赋值运算符
    BIGINT_FORCE_INLINE BigInteger& operator+=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator-=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator*=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator/=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator%=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator&=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator|=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator^=(const BigInteger& other);
    BIGINT_FORCE_INLINE BigInteger& operator<<=(int shift);
    BIGINT_FORCE_INLINE BigInteger& operator>>=(int shift);

    // 5. 二元运算符 (定义为友元以支持隐式转换，如 1 + a)
    friend BigInteger operator+(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator-(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator*(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator/(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator%(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator&(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator|(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator^(const BigInteger& lhs, const BigInteger& rhs);
    friend BigInteger operator<<(const BigInteger& lhs, int shift);
    friend BigInteger operator>>(const BigInteger& lhs, int shift);

    // 6. IO 流运算符
    friend std::ostream& operator<<(std::ostream& os, const BigInteger& bi);
    friend std::istream& operator>>(std::istream& is, BigInteger& bi);

    // ----------------------------------------------------------------------
    // 高级数学接口
    // ----------------------------------------------------------------------
    // 逻辑右移
    BIGINT_FORCE_INLINE BigInteger shift_right_logical(int shift_bits) const;
    // 循环移位
    BIGINT_FORCE_INLINE BigInteger rotate_left(int shift_bits, int total_bits) const;
    BIGINT_FORCE_INLINE BigInteger rotate_right(int shift_bits, int total_bits) const;

    // 数论操作
    BIGINT_FORCE_INLINE BigInteger mod_add(const BigInteger& other, const BigInteger& modulus) const;
    BIGINT_FORCE_INLINE BigInteger mod_subtract(const BigInteger& other, const BigInteger& modulus) const;
    BIGINT_FORCE_INLINE BigInteger mod_multiply(const BigInteger& other, const BigInteger& modulus) const;
    BIGINT_FORCE_INLINE BigInteger mod_pow(const BigInteger& exponent, const BigInteger& modulus) const;
    BIGINT_FORCE_INLINE BigInteger mod_inverse(const BigInteger& modulus) const;

    BIGINT_FORCE_INLINE BigInteger gcd(const BigInteger& other) const;
    BIGINT_FORCE_INLINE ExtendedGcdResult extended_gcd(const BigInteger& other) const;
    BIGINT_FORCE_INLINE int jacobi(const BigInteger& n) const;
};

// 自定义字面量 (e.g., 123456789_bi)
BigInteger operator""_bi(const char* str, size_t);

// --------------------------------------------------------------------------
// 结果结构体定义
// --------------------------------------------------------------------------
struct DivisionResult {
    BigInteger quotient;   ///< 商
    BigInteger remainder;  ///< 余数
};

struct ExtendedGcdResult {
    BigInteger gcd; ///< 最大公约数
    BigInteger x;   ///< 系数 x
    BigInteger y;   ///< 系数 y
};

// --------------------------------------------------------------------------
// 运算类 BigIntegerOps 定义
// --------------------------------------------------------------------------

class BigIntegerOps {
public:
    using Complex = std::complex<double>;

    // FFT / NTT
    BIGINT_FORCE_INLINE static void fft(std::vector<Complex>& a, bool invert);
    BIGINT_FORCE_INLINE static int next_power_of_two(int n);
    BIGINT_FORCE_INLINE static void ntt(std::vector<BigInteger>& a, bool invert, const BigInteger& MOD);
    BIGINT_FORCE_INLINE static BigInteger primitive_root(const BigInteger& MOD);
    BIGINT_FORCE_INLINE static std::vector<BigInteger> convolution(const std::vector<BigInteger>& a, const std::vector<BigInteger>& b, const BigInteger& MOD);

    // 基础向量运算
    BIGINT_FORCE_INLINE static std::vector<uint8_t> multiply_vector(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2);
    BIGINT_FORCE_INLINE static std::vector<uint8_t> multiply_simple(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2);
    BIGINT_FORCE_INLINE static std::vector<uint8_t> multiply_karatsuba(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2);
    BIGINT_FORCE_INLINE static std::vector<uint8_t> multiply_fft(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2);
    BIGINT_FORCE_INLINE static std::vector<uint8_t> multiply_ntt(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2);

    BIGINT_FORCE_INLINE static std::vector<uint8_t> add_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    BIGINT_FORCE_INLINE static std::vector<uint8_t> subtract_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // 核心逻辑
    BIGINT_FORCE_INLINE static int compare_absolute(const BigInteger& a, const BigInteger& b);

    BIGINT_FORCE_INLINE static BigInteger add(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static BigInteger subtract(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static BigInteger multiply(const BigInteger& a, const BigInteger& b);

    // 除法
    BIGINT_FORCE_INLINE static DivisionResult divide_and_remainder(const BigInteger& dividend, const BigInteger& divisor);
    BIGINT_FORCE_INLINE static DivisionResult basic_divide(const BigInteger& dividend, const BigInteger& divisor);
    // 注意：为简化头文件，保留basic_divide作为主实现，更复杂的除法算法建议在cpp中实现或此处扩展

    // 模运算
    BIGINT_FORCE_INLINE static BigInteger mod(const BigInteger& a, const BigInteger& modulus);
    BIGINT_FORCE_INLINE static BigInteger mod_add(const BigInteger& a, const BigInteger& b, const BigInteger& modulus);
    BIGINT_FORCE_INLINE static BigInteger mod_subtract(const BigInteger& a, const BigInteger& b, const BigInteger& modulus);
    BIGINT_FORCE_INLINE static BigInteger mod_inverse(const BigInteger& a, const BigInteger& modulus);
    BIGINT_FORCE_INLINE static BigInteger mod_multiply(const BigInteger& a, const BigInteger& b, const BigInteger& modulus);
    BIGINT_FORCE_INLINE static BigInteger mod_pow(const BigInteger& base, const BigInteger& exponent, const BigInteger& modulus);

    // 位运算
    BIGINT_FORCE_INLINE static BigInteger bit_and(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static BigInteger bit_or(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static BigInteger bit_xor(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static BigInteger bit_not(const BigInteger& a);
    BIGINT_FORCE_INLINE static BigInteger shift_left(const BigInteger& a, int shift_bits);
    BIGINT_FORCE_INLINE static BigInteger shift_right(const BigInteger& a, int shift_bits);
    BIGINT_FORCE_INLINE static BigInteger shift_right_logical(const BigInteger& a, int shift_bits);
    BIGINT_FORCE_INLINE static BigInteger rotate_left(const BigInteger& a, int shift_bits, int total_bits);
    BIGINT_FORCE_INLINE static BigInteger rotate_right(const BigInteger& a, int shift_bits, int total_bits);

    // 辅助
    BIGINT_FORCE_INLINE static BigInteger power(const BigInteger& base, const BigInteger& exponent);
    BIGINT_FORCE_INLINE static BigInteger divide_by_two(const BigInteger& a);
    BIGINT_FORCE_INLINE static bool is_odd(const BigInteger& a);
    BIGINT_FORCE_INLINE static int jacobi(const BigInteger& a, const BigInteger& n);

    BIGINT_FORCE_INLINE static BigInteger gcd(const BigInteger& a, const BigInteger& b);
    BIGINT_FORCE_INLINE static ExtendedGcdResult extended_gcd(const BigInteger& a, const BigInteger& b);

    // 内部工具
    BIGINT_FORCE_INLINE static BigInteger right_shift_bytes(const BigInteger& x, int n);
    BIGINT_FORCE_INLINE static BigInteger mask_lower_bytes(const BigInteger& x, int n);
    BIGINT_FORCE_INLINE static BigInteger pow_base(int n);

    // 嵌套类：Montgomery 约简
    class Montgomery {
    private:
        BigInteger N;
        BigInteger R;
        BigInteger N_prime;
        int k;
        BigInteger RR;

    public:
        Montgomery(const BigInteger& modulus);
        BigInteger transform(const BigInteger& a);
        BigInteger reduce(const BigInteger& a);
        BigInteger multiply(const BigInteger& a, const BigInteger& b);
        const BigInteger& get_modulus() const { return N; }
    };

    // 嵌套类：Barrett 约简
    class Barrett {
    private:
        BigInteger modulus;
        BigInteger mu;
        int k;

    public:
        Barrett(const BigInteger& mod);
        BigInteger reduce(const BigInteger& x);
        const BigInteger& get_modulus() const { return modulus; }
    };
};

// --------------------------------------------------------------------------
// 全局工具函数
// --------------------------------------------------------------------------

BIGINT_FORCE_INLINE inline BigInteger random_bigint(int bits);
BIGINT_FORCE_INLINE inline BigInteger random_bigint_range(const BigInteger& lower, const BigInteger& upper);
BIGINT_FORCE_INLINE inline bool is_prime(const BigInteger& n, int k = 20);
BIGINT_FORCE_INLINE inline BigInteger random_prime(int bits);
BIGINT_FORCE_INLINE inline BigInteger chinese_remainder_theorem(const std::vector<BigInteger>& remainders, const std::vector<BigInteger>& mods);

// --------------------------------------------------------------------------
// 实现部分 (Inline Implementation)
// --------------------------------------------------------------------------

// BigInteger 私有/工具方法

inline void BigInteger::remove_leading_zeros() {
    while (mag.size() > 1 && mag.back() == 0) {
        mag.pop_back();
    }
    if (mag.empty() || (mag.size() == 1 && mag[0] == 0)) {
        sign = false;
    }
}

inline void BigInteger::decimal_string_to_mag(const std::string_view numStr) {
    mag.clear();
    mag.push_back(0);

    for (char c : numStr) {
        uint32_t carry = c - '0';
        for (size_t i = 0; i < mag.size() || carry > 0; i++) {
            if (i >= mag.size()) mag.push_back(0);
            uint32_t val = mag[i] * 10 + carry;
            mag[i] = static_cast<uint8_t>(val % BASE);
            carry = val / BASE;
        }
    }
    remove_leading_zeros();
}

inline void BigInteger::binary_string_to_mag(const std::string_view binStr) {
    mag.clear();
    mag.push_back(0);

    for (char c : binStr) {
        if (c != '0' && c != '1') throw std::invalid_argument("Invalid binary string");
        uint32_t carry = c - '0';
        for (size_t i = 0; i < mag.size() || carry > 0; i++) {
            if (i >= mag.size()) mag.push_back(0);
            uint32_t val = mag[i] * 2 + carry;
            mag[i] = static_cast<uint8_t>(val % BASE);
            carry = val / BASE;
        }
    }
    remove_leading_zeros();
}

inline void BigInteger::hex_string_to_mag(const std::string_view hexStr) {
    mag.clear();
    mag.push_back(0);

    for (char c : hexStr) {
        char lowerC = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        size_t pos = HEX_CHARS.find(lowerC);
        if (pos == std::string::npos) throw std::invalid_argument("Invalid hexadecimal string");

        uint32_t val = static_cast<uint32_t>(pos);
        uint32_t carry = val;
        for (size_t i = 0; i < mag.size() || carry > 0; i++) {
            if (i >= mag.size()) mag.push_back(0);
            uint32_t total = mag[i] * 16 + carry;
            mag[i] = static_cast<uint8_t>(total % BASE);
            carry = total / BASE;
        }
    }
    remove_leading_zeros();
}

// 构造函数实现

inline BigInteger::BigInteger() : sign(false) {
    mag.push_back(0);
}

inline BigInteger::BigInteger(const std::string_view str) : sign(false) {
    if (str.empty()) { mag.push_back(0); return; }

    std::string_view numStr = str;
    if (numStr[0] == '-') { sign = true; numStr = numStr.substr(1); }
    else if (numStr[0] == '+') { sign = false; numStr = numStr.substr(1); }

    if (numStr.size() >= 2 && numStr[0] == '0') {
        if (numStr.size() > 2 && (numStr[1] == 'b' || numStr[1] == 'B')) {
            binary_string_to_mag(numStr.substr(2));
            return;
        }
        if (numStr.size() > 2 && (numStr[1] == 'x' || numStr[1] == 'X')) {
            hex_string_to_mag(numStr.substr(2));
            return;
        }
    }

    for (char c : numStr) {
        if (!isdigit(c)) throw std::invalid_argument("Invalid decimal string");
    }
    decimal_string_to_mag(numStr);
}

inline BigInteger::BigInteger(const std::string_view str, int base) : sign(false) {
    if (base != 2 && base != 10 && base != 16) throw std::invalid_argument("Base must be 2, 10, or 16");

    std::string_view numStr = str;
    if (numStr.empty()) { mag.push_back(0); return; }

    if (numStr[0] == '-') { sign = true; numStr = numStr.substr(1); }
    else if (numStr[0] == '+') { sign = false; numStr = numStr.substr(1); }

    switch (base) {
        case 2: binary_string_to_mag(numStr); break;
        case 10: decimal_string_to_mag(numStr); break;
        case 16: hex_string_to_mag(numStr); break;
    }
}

inline BigInteger::BigInteger(const std::span<const std::uint8_t> bytes, bool is_negative) : sign(is_negative) {
    mag = std::vector<std::uint8_t>{bytes.begin(), bytes.end()};
    remove_leading_zeros();
    if (mag.empty()) { mag.push_back(0); sign = false; }
}

inline BigInteger::BigInteger(const uint8_t* bytes, size_t length, bool is_negative) : sign(is_negative) {
    if (bytes == nullptr || length == 0) {
        mag.push_back(0);
        sign = false;
        return;
    }
    mag.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        mag.push_back(bytes[length - 1 - i]);
    }
    remove_leading_zeros();
}

inline BigInteger::BigInteger(long long num) {
    if (num < 0) { sign = true; num = -num; }
    else { sign = false; }

    if (num == 0) { mag.push_back(0); return; }

    while (num > 0) {
        mag.push_back(static_cast<uint8_t>(num % BASE));
        num /= BASE;
    }
}

inline BigInteger::BigInteger(unsigned long long num) : sign(false) {
    if (num == 0) { mag.push_back(0); return; }
    while (num > 0) {
        mag.push_back(static_cast<uint8_t>(num % BASE));
        num /= BASE;
    }
}

// 转换方法

inline std::string BigInteger::to_string() const {
    if (mag.empty() || (mag.size() == 1 && mag[0] == 0)) return "0";

    std::string result;
    std::vector<uint8_t> temp = mag;

    while (true) {
        uint32_t carry = 0;
        for (int i = temp.size() - 1; i >= 0; i--) {
            uint32_t val = carry * BASE + temp[i];
            temp[i] = static_cast<uint8_t>(val / 10);
            carry = val % 10;
        }
        result.push_back('0' + carry);
        while (!temp.empty() && temp.back() == 0) temp.pop_back();
        if (temp.empty()) break;
    }

    if (sign) result.push_back('-');
    std::reverse(result.begin(), result.end());
    return result;
}

inline std::string BigInteger::to_binary_string() const {
    if (is_zero()) return "0";
    std::string result;
    std::vector<uint8_t> temp = mag;
    while (true) {
        uint32_t carry = 0;
        for (int i = temp.size() - 1; i >= 0; i--) {
            uint32_t val = carry * BASE + temp[i];
            temp[i] = static_cast<uint8_t>(val / 2);
            carry = val % 2;
        }
        result.push_back('0' + carry);
        while (!temp.empty() && temp.back() == 0) temp.pop_back();
        if (temp.empty()) break;
    }
    if (sign) result.push_back('-');
    std::reverse(result.begin(), result.end());
    return result;
}

inline std::string BigInteger::to_hex_string(bool uppercase) const {
    if (is_zero()) return "0";
    std::string result;
    std::vector<uint8_t> temp = mag;
    while (true) {
        uint32_t carry = 0;
        for (int i = temp.size() - 1; i >= 0; i--) {
            uint32_t val = carry * BASE + temp[i];
            temp[i] = static_cast<uint8_t>(val / 16);
            carry = val % 16;
        }
        char hexChar = HEX_CHARS[carry];
        result.push_back(uppercase ? hexChar : static_cast<char>(tolower(hexChar)));
        while (!temp.empty() && temp.back() == 0) temp.pop_back();
        if (temp.empty()) break;
    }
    if (sign) result.push_back('-');
    std::reverse(result.begin(), result.end());
    return result;
}

inline std::vector<uint8_t> BigInteger::to_bytes() const {
    return mag;
}

inline BigInteger::operator bool() const {
    return !is_zero();
}

inline BigInteger::operator long long() const {
    long long res = 0;
    long long multiplier = 1;
    // 只取能容纳的部分，模拟标准整型截断行为
    for (size_t i = 0; i < mag.size() && i < sizeof(long long); ++i) {
        res += mag[i] * multiplier;
        multiplier *= BASE;
    }
    return sign ? -res : res;
}

inline long long BigInteger::to_long_long_checked() const {
    if (*this > BigInteger(std::numeric_limits<long long>::max()) ||
        *this < BigInteger(std::numeric_limits<long long>::min())) {
        throw std::overflow_error("BigInteger too large for long long");
    }
    return static_cast<long long>(*this);
}

inline void BigInteger::set_bytes(const std::vector<uint8_t>& bytes) {
    mag = bytes;
    remove_leading_zeros();
}

inline bool BigInteger::is_zero() const {
    return mag.size() == 1 && mag[0] == 0;
}

inline void BigInteger::swap(BigInteger& other) noexcept{
    mag.swap(other.mag);
    std::swap(sign, other.sign);
}

inline uint8_t BigInteger::mod4() const {
    return mag.empty() ? 0 : (mag[0] & 0x03);
}

inline uint8_t BigInteger::mod8() const {
    return mag.empty() ? 0 : (mag[0] & 0x07);
}

// --------------------------------------------------------------------------
// BigIntegerOps 实现
// --------------------------------------------------------------------------

// 位运算
inline BigInteger BigIntegerOps::bit_and(const BigInteger& a, const BigInteger& b) {
    const auto& magA = a.mag;
    const auto& magB = b.mag;
    size_t minLen = std::min(magA.size(), magB.size());
    std::vector<uint8_t> resultMag;
    for (size_t i = 0; i < minLen; ++i) {
        resultMag.push_back(magA[i] & magB[i]);
    }
    while (resultMag.size() > 1 && resultMag.back() == 0) resultMag.pop_back();
    // 简化处理：正数的位运算直接操作，负数理论上应转补码，此处仅支持绝对值按位操作
    return BigInteger(resultMag, false);
}

inline BigInteger BigIntegerOps::shift_left(const BigInteger& a, int shift_bits) {
    if (shift_bits < 0) throw std::invalid_argument("Shift bits must be non-negative");
    if (shift_bits == 0 || a.is_zero()) return a;

    const auto& mag = a.mag;
    int byte_shift = shift_bits / BASE_BITS;
    int bit_shift = shift_bits % BASE_BITS;

    std::vector<uint8_t> result(mag.size() + byte_shift + 1, 0);
    std::copy(mag.begin(), mag.end(), result.begin() + byte_shift);

    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (size_t i = byte_shift; i < result.size(); i++) {
            uint32_t val = (static_cast<uint32_t>(result[i]) << bit_shift) + carry;
            result[i] = static_cast<uint8_t>(val & 0xFF);
            carry = val >> BASE_BITS;
        }
        while (carry > 0) {
            result.push_back(static_cast<uint8_t>(carry & 0xFF));
            carry >>= BASE_BITS;
        }
    }
    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return BigInteger(result, a.sign);
}

inline BigInteger BigIntegerOps::shift_right(const BigInteger& a, int shift_bits) {
    if (shift_bits < 0) throw std::invalid_argument("Shift bits must be non-negative");
    if (shift_bits == 0 || a.is_zero()) return a;

    const auto& mag = a.mag;
    int byte_shift = shift_bits / BASE_BITS;
    int bit_shift = shift_bits % BASE_BITS;

    if (byte_shift >= static_cast<int>(mag.size())) return BigInteger("0");

    std::vector<uint8_t> result(mag.begin() + byte_shift, mag.end());

    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (int i = result.size() - 1; i >= 0; i--) {
            uint32_t val = (static_cast<uint32_t>(result[i]) >> bit_shift) | carry;
            carry = (result[i] << (BASE_BITS - bit_shift)) & 0xFF;
            result[i] = static_cast<uint8_t>(val);
        }
    }
    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return BigInteger(result, a.sign); // 算术右移，符号不变
}

inline BigInteger BigIntegerOps::shift_right_logical(const BigInteger& a, int shift_bits) {
    BigInteger res = shift_right(a, shift_bits);
    res.set_sign(false);
    return res;
}

inline BigInteger BigIntegerOps::right_shift_bytes(const BigInteger& x, int n) {
    if (n <= 0) return x;
    const auto& mag = x.mag;
    if (n >= static_cast<int>(mag.size())) return BigInteger(0);
    std::vector<uint8_t> shifted(mag.begin() + n, mag.end());
    return BigInteger(shifted, x.sign);
}

inline BigInteger BigIntegerOps::mask_lower_bytes(const BigInteger& x, int n) {
    if (n <= 0) return BigInteger(0);
    const auto& mag = x.mag;
    std::vector<uint8_t> masked;
    for (int i = 0; i < n && i < static_cast<int>(mag.size()); ++i) {
        masked.push_back(mag[i]);
    }
    return BigInteger(masked, false);
}

inline BigInteger BigIntegerOps::bit_or(const BigInteger& a, const BigInteger& b) {
    const auto& magA = a.mag;
    const auto& magB = b.mag;
    size_t maxLen = std::max(magA.size(), magB.size());
    std::vector<uint8_t> resultMag(maxLen, 0);
    for (size_t i = 0; i < maxLen; ++i) {
        uint8_t byteA = (i < magA.size()) ? magA[i] : 0;
        uint8_t byteB = (i < magB.size()) ? magB[i] : 0;
        resultMag[i] = byteA | byteB;
    }
    while (resultMag.size() > 1 && resultMag.back() == 0) resultMag.pop_back();
    return BigInteger(resultMag, false);
}

inline BigInteger BigIntegerOps::bit_not(const BigInteger& a) {
    // 模拟按位取反：~x = -x - 1
    return BigIntegerOps::subtract(BigIntegerOps::subtract(BigInteger("0"), a), BigInteger("1"));
}

inline BigInteger BigIntegerOps::bit_xor(const BigInteger& a, const BigInteger& b) {
    const auto& magA = a.mag;
    const auto& magB = b.mag;
    size_t maxLen = std::max(magA.size(), magB.size());
    std::vector<uint8_t> resultMag(maxLen, 0);
    for (size_t i = 0; i < maxLen; ++i) {
        uint8_t byteA = (i < magA.size()) ? magA[i] : 0;
        uint8_t byteB = (i < magB.size()) ? magB[i] : 0;
        resultMag[i] = byteA ^ byteB;
    }
    while (resultMag.size() > 1 && resultMag.back() == 0) resultMag.pop_back();
    return BigInteger(resultMag, false);
}

inline BigInteger BigIntegerOps::rotate_left(const BigInteger& a, int shift_bits, int total_bits) {
    if (total_bits <= 0 || shift_bits <= 0) return a;
    shift_bits %= total_bits;
    if (shift_bits == 0) return a;

    std::vector<bool> bits(total_bits, false);
    const auto& mag = a.mag;
    for (size_t i = 0; i < mag.size() && i * 8 < static_cast<size_t>(total_bits); ++i) {
        for (int j = 0; j < 8 && static_cast<int>(i * 8 + j) < total_bits; ++j) {
            bits[i * 8 + j] = (mag[i] >> j) & 1;
        }
    }

    std::vector<bool> result_bits(total_bits);
    for (int i = 0; i < total_bits; ++i) {
        result_bits[(i + shift_bits) % total_bits] = bits[i];
    }

    std::vector<uint8_t> result_mag((total_bits + 7) / 8, 0);
    for (int i = 0; i < total_bits; ++i) {
        if (result_bits[i]) result_mag[i / 8] |= (1 << (i % 8));
    }
    while (result_mag.size() > 1 && result_mag.back() == 0) result_mag.pop_back();
    return BigInteger(result_mag, false);
}

inline BigInteger BigIntegerOps::rotate_right(const BigInteger& a, int shift_bits, int total_bits) {
    if (total_bits <= 0 || shift_bits <= 0) return a;
    shift_bits %= total_bits;
    if (shift_bits == 0) return a;
    return rotate_left(a, total_bits - shift_bits, total_bits);
}

// 比较运算
inline int BigIntegerOps::compare_absolute(const BigInteger& a, const BigInteger& b) {
    const auto& magA = a.mag;
    const auto& magB = b.mag;
    if (magA.size() != magB.size()) return magA.size() > magB.size() ? 1 : -1;
    for (int i = magA.size() - 1; i >= 0; i--) {
        if (magA[i] != magB[i]) return magA[i] > magB[i] ? 1 : -1;
    }
    return 0;
}

// 加减运算
inline std::vector<uint8_t> BigIntegerOps::add_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    size_t lenA = a.size();
    size_t lenB = b.size();
    size_t maxLen = std::max(lenA, lenB);
    std::vector<uint8_t> result;
    result.reserve(maxLen + 1);

    uint32_t carry = 0;
    for (size_t i = 0; i < maxLen || carry > 0; ++i) {
        uint32_t valA = (i < lenA) ? a[i] : 0;
        uint32_t valB = (i < lenB) ? b[i] : 0;
        uint32_t sum = valA + valB + carry;
        result.push_back(static_cast<uint8_t>(sum % BASE));
        carry = sum / BASE;
    }
    return result;
}

inline std::vector<uint8_t> BigIntegerOps::subtract_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    size_t lenA = a.size();
    size_t lenB = b.size();
    std::vector<uint8_t> result;
    result.reserve(lenA);

    int32_t borrow = 0;
    for (size_t i = 0; i < lenA; ++i) {
        uint32_t valA = a[i];
        uint32_t valB = (i < lenB) ? b[i] : 0;
        int32_t diff = static_cast<int32_t>(valA) - static_cast<int32_t>(valB) - borrow;
        if (diff < 0) {
            diff += BASE;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result.push_back(static_cast<uint8_t>(diff));
    }
    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return result;
}

inline BigInteger BigIntegerOps::add(const BigInteger& a, const BigInteger& b) {
    if (a.is_zero()) return b;
    if (b.is_zero()) return a;

    if (a.sign == b.sign) {
        return BigInteger(add_vectors(a.mag, b.mag), a.sign);
    }

    int absCmp = compare_absolute(a, b);
    if (absCmp == 0) return BigInteger("0");

    if (absCmp > 0) {
        return BigInteger(subtract_vectors(a.mag, b.mag), a.sign);
    } else {
        return BigInteger(subtract_vectors(b.mag, a.mag), b.sign);
    }
}

inline BigInteger BigIntegerOps::subtract(const BigInteger& a, const BigInteger& b) {
    if (b.is_zero()) return a;
    if (a == b) return BigInteger("0");
    BigInteger negB = b;
    negB.set_sign(!negB.get_sign());
    return add(a, negB);
}

// 乘法运算
inline void BigIntegerOps::fft(std::vector<Complex>& a, bool invert) {
    int n = a.size();
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }

    for (int len = 2; len <= n; len <<= 1) {
        double angle = 2 * std::numbers::pi / len * (invert ? -1 : 1);
        Complex wlen(std::cos(angle), std::sin(angle));
        for (int i = 0; i < n; i += len) {
            Complex w(1);
            for (int j = 0; j < len / 2; j++) {
                Complex u = a[i + j];
                Complex v = a[i + j + len / 2] * w;
                a[i + j] = u + v;
                a[i + j + len / 2] = u - v;
                w *= wlen;
            }
        }
    }
    if (invert) {
        for (Complex& x : a) x /= n;
    }
}

inline int BigIntegerOps::next_power_of_two(int n) {
    int power = 1;
    while (power < n) power <<= 1;
    return power;
}

inline BigInteger BigIntegerOps::primitive_root(const BigInteger& MOD) {
    if (MOD == BigInteger("998244353")) return BigInteger("3");
    if (MOD == BigInteger("1004535809")) return BigInteger("3");
    if (MOD == BigInteger("1092616193")) return BigInteger("3");
    // 简化处理，实际应完整实现寻找原根
    return BigInteger("0");
}

inline void BigIntegerOps::ntt(std::vector<BigInteger>& a, bool invert, const BigInteger& MOD) {
    int n = a.size();
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    for (int len = 2; len <= n; len <<= 1) {
        BigInteger wlen = primitive_root(MOD);
        BigInteger exponent = (MOD - BigInteger(1)) / BigInteger(len);
        if (invert) exponent = MOD - BigInteger(1) - exponent;
        wlen = wlen.mod_pow(exponent, MOD);
        for (int i = 0; i < n; i += len) {
            BigInteger w(1);
            for (int j = 0; j < len / 2; j++) {
                BigInteger u = a[i + j];
                BigInteger v = mod(a[i + j + len / 2] * w, MOD);
                a[i + j] = mod(u + v, MOD);
                a[i + j + len / 2] = mod(u - v, MOD);
                if (a[i + j + len / 2].get_sign()) {
                    a[i + j + len / 2] = a[i + j + len / 2] + MOD;
                }
                w = mod(w * wlen, MOD);
            }
        }
    }
    if (invert) {
        BigInteger n_inv = BigInteger(n).mod_inverse(MOD);
        for (int i = 0; i < n; i++) a[i] = mod(a[i] * n_inv, MOD);
    }
}

inline std::vector<BigInteger> BigIntegerOps::convolution(const std::vector<BigInteger>& a, const std::vector<BigInteger>& b, const BigInteger& MOD) {
    int n = 1;
    while (n < static_cast<int>(a.size() + b.size())) n <<= 1;
    std::vector<BigInteger> fa(a.begin(), a.end()), fb(b.begin(), b.end());
    fa.resize(n, BigInteger("0"));
    fb.resize(n, BigInteger("0"));
    ntt(fa, false, MOD);
    ntt(fb, false, MOD);
    for (int i = 0; i < n; i++) fa[i] = mod(fa[i] * fb[i], MOD);
    ntt(fa, true, MOD);
    return fa;
}

inline std::vector<uint8_t> BigIntegerOps::multiply_simple(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2) {
    int n = num1.size();
    int m = num2.size();
    std::vector<uint8_t> result(n + m, 0);
    std::vector<uint32_t> temp(n + m, 0);
    for (int i = 0; i < n; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < m || carry > 0; j++) {
            uint32_t prod = carry;
            if (j < m) prod += static_cast<uint32_t>(num1[i]) * num2[j];
            prod += temp[i + j];
            temp[i + j] = prod % BASE;
            carry = prod / BASE;
        }
    }
    for (size_t i = 0; i < temp.size(); i++) result[i] = static_cast<uint8_t>(temp[i]);
    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return result;
}

inline std::vector<uint8_t> BigIntegerOps::multiply_karatsuba(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2) {
    int n = std::max(num1.size(), num2.size());
    if (n <= 32) return multiply_simple(num1, num2);
    n = (n + 1) / 2;

    std::vector<uint8_t> a0, a1, b0, b1;
    if (num1.size() <= static_cast<size_t>(n)) { a0 = num1; a1.push_back(0); }
    else { a0.assign(num1.begin(), num1.begin() + n); a1.assign(num1.begin() + n, num1.end()); }

    if (num2.size() <= static_cast<size_t>(n)) { b0 = num2; b1.push_back(0); }
    else { b0.assign(num2.begin(), num2.begin() + n); b1.assign(num2.begin() + n, num2.end()); }

    while (a0.size() > 1 && a0.back() == 0) a0.pop_back();
    while (a1.size() > 1 && a1.back() == 0) a1.pop_back();
    while (b0.size() > 1 && b0.back() == 0) b0.pop_back();
    while (b1.size() > 1 && b1.back() == 0) b1.pop_back();

    auto z0 = multiply_karatsuba(a0, b0);
    auto z2 = multiply_karatsuba(a1, b1);
    auto z1 = multiply_karatsuba(add_vectors(a0, a1), add_vectors(b0, b1));
    z1 = subtract_vectors(z1, z0);
    z1 = subtract_vectors(z1, z2);

    std::vector<uint8_t> result = z0;

    auto add_shifted = [&](const std::vector<uint8_t>& z, int shift) {
        for (size_t i = 0; i < z.size(); i++) {
            size_t pos = i + shift;
            while (result.size() <= pos) result.push_back(0);
            uint32_t sum = static_cast<uint32_t>(result[pos]) + static_cast<uint32_t>(z[i]);
            result[pos] = static_cast<uint8_t>(sum % BASE);
            uint32_t carry = sum / BASE;
            size_t carry_pos = pos + 1;
            while (carry > 0) {
                while (result.size() <= carry_pos) result.push_back(0);
                uint32_t new_sum = static_cast<uint32_t>(result[carry_pos]) + carry;
                result[carry_pos] = static_cast<uint8_t>(new_sum % BASE);
                carry = new_sum / BASE;
                carry_pos++;
            }
        }
    };

    add_shifted(z1, n);
    add_shifted(z2, 2 * n);

    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return result;
}

inline std::vector<uint8_t> BigIntegerOps::multiply_fft(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2) {
    int n = num1.size() + num2.size();
    int N = next_power_of_two(n);
    std::vector<Complex> fa(N), fb(N);
    for (size_t i = 0; i < num1.size(); ++i) fa[i] = num1[i];
    for (size_t i = 0; i < num2.size(); ++i) fb[i] = num2[i];
    fft(fa, false);
    fft(fb, false);
    for (int i = 0; i < N; ++i) fa[i] *= fb[i];
    fft(fa, true);

    std::vector<uint8_t> result;
    uint32_t carry = 0;
    for (int i = 0; i < N; ++i) {
        uint32_t val = static_cast<uint32_t>(fa[i].real() + 0.5) + carry;
        result.push_back(static_cast<uint8_t>(val % BASE));
        carry = val / BASE;
    }
    while (carry > 0) {
        result.push_back(static_cast<uint8_t>(carry % BASE));
        carry /= BASE;
    }
    while (result.size() > 1 && result.back() == 0) result.pop_back();
    return result;
}

inline std::vector<uint8_t> BigIntegerOps::multiply_ntt(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2) {
    if ((num1.size() == 1 && num1[0] == 0) || (num2.size() == 1 && num2[0] == 0)) return {0};
    // 简化：使用FFT作为通用fallback，完整NTT需中国剩余定理支持（代码过长省略）
    return multiply_fft(num1, num2);
}

inline std::vector<uint8_t> BigIntegerOps::multiply_vector(const std::vector<uint8_t>& num1, const std::vector<uint8_t>& num2) {
    if ((num1.size() == 1 && num1[0] == 0) || (num2.size() == 1 && num2[0] == 0)) return {0};
    if (num1.size() < 64 || num2.size() < 64) return multiply_simple(num1, num2);
    else if (num1.size() <= 512 || num2.size() <= 512) return multiply_karatsuba(num1, num2);
    return multiply_fft(num1, num2);
}

inline BigInteger BigIntegerOps::multiply(const BigInteger& a, const BigInteger& b) {
    if (a.is_zero() || b.is_zero()) return BigInteger("0");
    auto productMag = multiply_vector(a.mag, b.mag);
    return BigInteger(productMag, a.sign != b.sign);
}

// 除法实现

inline BigInteger BigIntegerOps::divide_by_two(const BigInteger& a) {
    const auto& mag = a.mag;
    std::vector<uint8_t> resultMag;
    uint32_t carry = 0;
    for (int i = mag.size() - 1; i >= 0; i--) {
        uint32_t current = carry * BASE + mag[i];
        resultMag.push_back(static_cast<uint8_t>(current / 2));
        carry = current % 2;
    }
    std::reverse(resultMag.begin(), resultMag.end());
    while (resultMag.size() > 1 && resultMag.back() == 0) resultMag.pop_back();
    return BigInteger(resultMag, a.sign);
}

inline DivisionResult BigIntegerOps::basic_divide(const BigInteger& dividend, const BigInteger& divisor) {
    if (divisor.is_zero()) throw std::invalid_argument("Division by zero");
    if (dividend.is_zero()) return {BigInteger("0"), BigInteger("0")};

    bool quotientSign = (dividend.sign != divisor.sign);
    bool remainderSign = dividend.sign;

    BigInteger dividendAbs = dividend; dividendAbs.set_sign(false);
    BigInteger divisorAbs = divisor; divisorAbs.set_sign(false);

    if (dividendAbs < divisorAbs) return {BigInteger("0"), dividend};

    BigInteger quotient("0");
    BigInteger remainder("0");

    const auto& dividendBytes = dividendAbs.mag;
    for (int i = dividendBytes.size() - 1; i >= 0; i--) {
        remainder = shift_left(remainder, BASE_BITS);
        remainder = add(remainder, BigInteger(static_cast<long long>(dividendBytes[i])));
        BigInteger digit("0");
        while (remainder >= divisorAbs) {
            remainder = subtract(remainder, divisorAbs);
            digit = add(digit, BigInteger("1"));
        }
        quotient = shift_left(quotient, BASE_BITS);
        quotient = add(quotient, digit);
    }
    quotient.set_sign(quotientSign);
    if (remainderSign && !remainder.is_zero()) remainder.set_sign(true);
    return {quotient, remainder};
}

inline DivisionResult BigIntegerOps::divide_and_remainder(const BigInteger& dividend, const BigInteger& divisor) {
    return basic_divide(dividend, divisor);
}

// 幂运算
inline BigInteger BigIntegerOps::power(const BigInteger& base, const BigInteger& exponent) {
    BigInteger res("1");
    BigInteger current = base;
    BigInteger exp = exponent;
    while (exp > BigInteger("0")) {
        if (is_odd(exp)) res = multiply(res, current);
        current = multiply(current, current);
        exp = divide_by_two(exp);
    }
    return res;
}

inline BigInteger BigIntegerOps::pow_base(int n) {
    if (n <= 0) return BigInteger(1);
    std::vector<uint8_t> powMag(n, 0);
    powMag.push_back(1);
    return BigInteger(powMag, false);
}

// 模运算
inline BigInteger BigIntegerOps::mod(const BigInteger& a, const BigInteger& modulus) {
    if (modulus.is_zero()) throw std::invalid_argument("Modulus cannot be zero");
    if (modulus == BigInteger("1") || modulus == BigInteger("-1")) return BigInteger("0");

    bool modIsNegative = modulus.sign;
    BigInteger modAbs = modulus; modAbs.set_sign(false);

    BigInteger result;
    if (a.sign) {
        BigInteger abs_a = a; abs_a.set_sign(false);
        result = divide_and_remainder(abs_a, modAbs).remainder;
        if (!result.is_zero()) result = subtract(modAbs, result);
        if (modIsNegative && !result.is_zero()) {
            result = subtract(modAbs, result);
            result.set_sign(true);
        }
    } else {
        result = divide_and_remainder(a, modAbs).remainder;
        if (modIsNegative && !result.is_zero()) {
            result = subtract(modAbs, result);
            result.set_sign(true);
        }
    }
    return result;
}

inline BigInteger BigIntegerOps::mod_add(const BigInteger& a, const BigInteger& b, const BigInteger& modulus) {
    return mod(add(a, b), modulus);
}
inline BigInteger BigIntegerOps::mod_subtract(const BigInteger& a, const BigInteger& b, const BigInteger& modulus) {
    return mod(subtract(a, b), modulus);
}

inline BigInteger BigIntegerOps::gcd(const BigInteger& a, const BigInteger& b) {
    if (a.is_zero()) return b;
    if (b.is_zero()) return a;
    BigInteger aa = a; aa.set_sign(false);
    BigInteger bb = b; bb.set_sign(false);
    int shift = 0;
    while (!is_odd(aa) && !is_odd(bb)) { aa = divide_by_two(aa); bb = divide_by_two(bb); shift++; }
    while (!is_odd(aa)) aa = divide_by_two(aa);
    do {
        while (!is_odd(bb)) bb = divide_by_two(bb);
        if (aa > bb) aa.swap(bb);
        bb = subtract(bb, aa);
    } while (!bb.is_zero());
    return aa << shift;
}

inline ExtendedGcdResult BigIntegerOps::extended_gcd(const BigInteger& a, const BigInteger& b) {
    if (a.is_zero()) return {b, BigInteger(0), BigInteger(1)};
    if (b.is_zero()) return {a, BigInteger(1), BigInteger(0)};

    BigInteger aa = a; aa.set_sign(false);
    BigInteger bb = b; bb.set_sign(false);
    BigInteger x1(1), y1(0), x2(0), y2(1);

    BigInteger r0 = aa, r1 = bb;
    while (!r1.is_zero()) {
        auto divRes = divide_and_remainder(r0, r1);
        BigInteger q = divRes.quotient;
        BigInteger r = divRes.remainder;

        BigInteger tempX = subtract(x1, multiply(q, x2));
        BigInteger tempY = subtract(y1, multiply(q, y2));

        x1 = x2; y1 = y2;
        x2 = tempX; y2 = tempY;
        r0 = r1; r1 = r;
    }
    return {r0, x1, y1};
}

inline BigInteger BigIntegerOps::mod_inverse(const BigInteger& a, const BigInteger& modulus) {
    if (modulus.is_zero() || modulus <= BigInteger("1")) throw std::invalid_argument("Modulus must be > 1");
    BigInteger aa = mod(a, modulus);
    if (aa.is_zero()) throw std::invalid_argument("Zero has no inverse");
    auto res = extended_gcd(aa, modulus);
    if (res.gcd != BigInteger("1")) throw std::invalid_argument("Inverse does not exist");
    BigInteger x = res.x;
    if (x.get_sign()) x = add(x, modulus);
    return mod(x, modulus);
}

inline BigInteger BigIntegerOps::mod_multiply(const BigInteger& a, const BigInteger& b, const BigInteger& modulus) {
    if (modulus.is_zero()) throw std::invalid_argument("Modulus zero");
    BigInteger ra = mod(a, modulus);
    BigInteger rb = mod(b, modulus);
    if (ra.is_zero() || rb.is_zero()) return BigInteger("0");
    if (is_odd(modulus)) {
        Montgomery mont(modulus);
        return mont.reduce(mont.multiply(mont.transform(ra), mont.transform(rb)));
    }
    return mod(multiply(ra, rb), modulus);
}

inline BigInteger BigIntegerOps::mod_pow(const BigInteger& base, const BigInteger& exponent, const BigInteger& modulus) {
    if (modulus <= BigInteger("0")) throw std::invalid_argument("Modulus must be positive");
    if (modulus == BigInteger("1")) return BigInteger("0");
    if (exponent.is_zero()) return BigInteger("1");
    if (base.is_zero()) return BigInteger("0");
    if (exponent < BigInteger("0")) throw std::invalid_argument("Negative exponents not supported");

    if (is_odd(modulus)) {
        Montgomery mont(modulus);
        BigInteger baseR = mont.transform(mod(base, modulus));
        BigInteger resultR = mont.transform(BigInteger("1"));
        BigInteger exp = exponent;
        std::vector<bool> bits;
        while (!exp.is_zero()) { bits.push_back(is_odd(exp)); exp = divide_by_two(exp); }
        for (int i = bits.size() - 1; i >= 0; --i) {
            resultR = mont.multiply(resultR, resultR);
            if (bits[i]) resultR = mont.multiply(resultR, baseR);
        }
        return mont.reduce(resultR);
    }
    // 普通快速幂
    BigInteger res("1");
    BigInteger cb = mod(base, modulus);
    BigInteger exp = exponent;
    while (exp > BigInteger("0")) {
        if (is_odd(exp)) res = mod_multiply(res, cb, modulus);
        cb = mod_multiply(cb, cb, modulus);
        exp = divide_by_two(exp);
    }
    return res;
}

inline bool BigIntegerOps::is_odd(const BigInteger& a) {
    return !a.mag.empty() && (a.mag[0] % 2 == 1);
}

inline int BigIntegerOps::jacobi(const BigInteger& a, const BigInteger& n) {
    if (n <= BigInteger("0") || !is_odd(n)) throw std::invalid_argument("n must be positive odd");
    if (a < BigInteger("0")) throw std::invalid_argument("a must be non-negative");
    if (gcd(a, n) != BigInteger("1")) return 0;
    if (a.is_zero()) return 0;
    if (a == BigInteger("1")) return 1;

    BigInteger aa = a % n;
    BigInteger nn = n;
    int result = 1;
    while (aa != BigInteger("1")) {
        uint8_t mod8 = nn.mod8();
        while (!is_odd(aa)) {
            aa = divide_by_two(aa);
            if (mod8 == 3 || mod8 == 5) result = -result;
        }
        aa.swap(nn);
        if (aa.mod4() == 3 && nn.mod4() == 3) result = -result;
        aa = aa % nn;
        if (aa.is_zero()) return 0;
    }
    return result;
}

// --------------------------------------------------------------------------
// Montgomery / Barrett 实现
// --------------------------------------------------------------------------

inline BigIntegerOps::Montgomery::Montgomery(const BigInteger& modulus) : N(modulus) {
    k = N.to_bytes().size();
    std::vector<uint8_t> rBytes(k + 1, 0);
    rBytes[k] = 1;
    R = BigInteger(rBytes, false);

    std::vector<uint8_t> nBytes = N.to_bytes();
    std::vector<uint8_t> nModRBytes(std::min(k, static_cast<int>(nBytes.size())), 0);
    for (int i = 0; i < static_cast<int>(nModRBytes.size()); ++i) nModRBytes[i] = nBytes[i];

    BigInteger nModR(nModRBytes, false);
    auto res = BigIntegerOps::extended_gcd(nModR, R);
    BigInteger x = res.x;
    if (x.get_sign()) x = BigIntegerOps::add(x, R);
    N_prime = BigIntegerOps::subtract(R, x);
    RR = BigIntegerOps::mod(BigIntegerOps::multiply(R, R), N);
}

inline BigInteger BigIntegerOps::Montgomery::transform(const BigInteger& a) {
    return BigIntegerOps::mod(BigIntegerOps::multiply(a, R), N);
}

inline BigInteger BigIntegerOps::Montgomery::reduce(const BigInteger& a) {
    const auto& aMag = a.mag;
    std::vector<uint8_t> lowKBytes(std::min(k, static_cast<int>(aMag.size())), 0);
    for (int i = 0; i < static_cast<int>(lowKBytes.size()); ++i) lowKBytes[i] = aMag[i];
    BigInteger aLow(lowKBytes, false);

    BigInteger m = BigIntegerOps::multiply(aLow, N_prime);
    const auto& mMag = m.mag;
    std::vector<uint8_t> mLow(std::min(k, static_cast<int>(mMag.size())), 0);
    for (int i = 0; i < static_cast<int>(mLow.size()); ++i) mLow[i] = mMag[i];
    m = BigInteger(mLow, false);

    BigInteger t = BigIntegerOps::add(a, BigIntegerOps::multiply(m, N));
    const auto& tMag = t.mag;
    if (static_cast<int>(tMag.size()) <= k) t = BigInteger("0");
    else {
        std::vector<uint8_t> tHigh(tMag.begin() + k, tMag.end());
        t = BigInteger(tHigh, false);
    }
    if (t >= N) t = BigIntegerOps::subtract(t, N);
    return t;
}

inline BigInteger BigIntegerOps::Montgomery::multiply(const BigInteger& a, const BigInteger& b) {
    return reduce(BigIntegerOps::multiply(a, b));
}

inline BigIntegerOps::Barrett::Barrett(const BigInteger& mod) : modulus(mod) {
    k = modulus.to_bytes().size();
    BigInteger base2k = BigIntegerOps::pow_base(2 * k);
    mu = BigIntegerOps::divide_and_remainder(base2k, modulus).quotient;
}

inline BigInteger BigIntegerOps::Barrett::reduce(const BigInteger& x) {
    if (x < modulus) return x;
    BigInteger q1 = BigIntegerOps::right_shift_bytes(x, k - 1);
    BigInteger q2 = BigIntegerOps::multiply(q1, mu);
    BigInteger q3 = BigIntegerOps::right_shift_bytes(q2, k + 1);
    BigInteger r1 = BigIntegerOps::mask_lower_bytes(x, k + 1);
    BigInteger r2 = BigIntegerOps::mask_lower_bytes(BigIntegerOps::multiply(q3, modulus), k + 1);
    BigInteger r = BigIntegerOps::subtract(r1, r2);
    while (r.get_sign()) r = BigIntegerOps::add(r, BigIntegerOps::pow_base(k + 1));
    while (r >= modulus) r = BigIntegerOps::subtract(r, modulus);
    return r;
}

// --------------------------------------------------------------------------
// BigInteger 成员函数 - 运算符实现
// --------------------------------------------------------------------------

// 1. 三路比较 (C++20)
inline std::strong_ordering BigInteger::operator<=>(const BigInteger& other) const {
    int cmp = BigIntegerOps::compare_absolute(*this, other);
    if (sign != other.sign) {
        // sign true=负, false=正. 如果this负(true) other正(false), return less
        return sign ? std::strong_ordering::less : std::strong_ordering::greater;
    }
    if (sign) { // 都是负数，绝对值大的更小
        cmp = -cmp; 
    }
    if (cmp > 0) return std::strong_ordering::greater;
    if (cmp < 0) return std::strong_ordering::less;
    return std::strong_ordering::equal;
}

inline bool BigInteger::operator==(const BigInteger& other) const {
    return (*this <=> other) == std::strong_ordering::equal;
}

// 2. 自增/自减
inline BigInteger& BigInteger::operator++() { // 前置
    *this = BigIntegerOps::add(*this, BigInteger("1"));
    return *this;
}
inline BigInteger BigInteger::operator++(int) { // 后置
    BigInteger temp = *this;
    ++(*this);
    return temp;
}
inline BigInteger& BigInteger::operator--() { // 前置
    *this = BigIntegerOps::subtract(*this, BigInteger("1"));
    return *this;
}
inline BigInteger BigInteger::operator--(int) { // 后置
    BigInteger temp = *this;
    --(*this);
    return temp;
}

// 3. 一元运算符
inline BigInteger BigInteger::operator+() const { return *this; }
inline BigInteger BigInteger::operator-() const {
    if (is_zero()) return *this;
    BigInteger res = *this;
    res.set_sign(!res.get_sign());
    return res;
}
inline BigInteger BigInteger::operator~() const { return BigIntegerOps::bit_not(*this); }
inline bool BigInteger::operator!() const { return is_zero(); }

// 4. 复合赋值
inline BigInteger& BigInteger::operator+=(const BigInteger& other) { *this = BigIntegerOps::add(*this, other); return *this; }
inline BigInteger& BigInteger::operator-=(const BigInteger& other) { *this = BigIntegerOps::subtract(*this, other); return *this; }
inline BigInteger& BigInteger::operator*=(const BigInteger& other) { *this = BigIntegerOps::multiply(*this, other); return *this; }
inline BigInteger& BigInteger::operator/=(const BigInteger& other) { *this = BigIntegerOps::divide_and_remainder(*this, other).quotient; return *this; }
// 按照 C++ 语义，a % b 的符号应与 a 相同
inline BigInteger& BigInteger::operator%=(const BigInteger& other) { *this = BigIntegerOps::divide_and_remainder(*this, other).remainder; return *this; }
inline BigInteger& BigInteger::operator&=(const BigInteger& other) { *this = BigIntegerOps::bit_and(*this, other); return *this; }
inline BigInteger& BigInteger::operator|=(const BigInteger& other) { *this = BigIntegerOps::bit_or(*this, other); return *this; }
inline BigInteger& BigInteger::operator^=(const BigInteger& other) { *this = BigIntegerOps::bit_xor(*this, other); return *this; }
inline BigInteger& BigInteger::operator<<=(int shift) { *this = BigIntegerOps::shift_left(*this, shift); return *this; }
inline BigInteger& BigInteger::operator>>=(int shift) { *this = BigIntegerOps::shift_right(*this, shift); return *this; }

// 5. 二元运算符 (Hidden Friends)
inline BigInteger operator+(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::add(lhs, rhs); }
inline BigInteger operator-(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::subtract(lhs, rhs); }
inline BigInteger operator*(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::multiply(lhs, rhs); }
inline BigInteger operator/(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::divide_and_remainder(lhs, rhs).quotient; }
inline BigInteger operator%(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::divide_and_remainder(lhs, rhs).remainder; }
inline BigInteger operator&(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::bit_and(lhs, rhs); }
inline BigInteger operator|(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::bit_or(lhs, rhs); }
inline BigInteger operator^(const BigInteger& lhs, const BigInteger& rhs) { return BigIntegerOps::bit_xor(lhs, rhs); }
inline BigInteger operator<<(const BigInteger& lhs, int shift) { return BigIntegerOps::shift_left(lhs, shift); }
inline BigInteger operator>>(const BigInteger& lhs, int shift) { return BigIntegerOps::shift_right(lhs, shift); }

// 6. IO 流
inline std::ostream& operator<<(std::ostream& os, const BigInteger& bi) {
    os << bi.to_string();
    return os;
}
inline std::istream& operator>>(std::istream& is, BigInteger& bi) {
    std::string s;
    is >> s;
    if (is) bi = BigInteger(s);
    return is;
}

// 高级接口包装
inline BigInteger BigInteger::rotate_left(int shift_bits, int total_bits) const { return BigIntegerOps::rotate_left(*this, shift_bits, total_bits); }
inline BigInteger BigInteger::rotate_right(int shift_bits, int total_bits) const { return BigIntegerOps::rotate_right(*this, shift_bits, total_bits); }
inline BigInteger BigInteger::shift_right_logical(int shift_bits) const { return BigIntegerOps::shift_right_logical(*this, shift_bits); }
inline BigInteger BigInteger::mod_add(const BigInteger& other, const BigInteger& modulus) const { return BigIntegerOps::mod_add(*this, other, modulus); }
inline BigInteger BigInteger::mod_subtract(const BigInteger& other, const BigInteger& modulus) const { return BigIntegerOps::mod_subtract(*this, other, modulus); }
inline BigInteger BigInteger::mod_multiply(const BigInteger& other, const BigInteger& modulus) const { return BigIntegerOps::mod_multiply(*this, other, modulus); }
inline BigInteger BigInteger::mod_pow(const BigInteger& exponent, const BigInteger& modulus) const { return BigIntegerOps::mod_pow(*this, exponent, modulus); }
inline BigInteger BigInteger::mod_inverse(const BigInteger& modulus) const { return BigIntegerOps::mod_inverse(*this, modulus); }
inline BigInteger BigInteger::gcd(const BigInteger& other) const { return BigIntegerOps::gcd(*this, other); }
inline ExtendedGcdResult BigInteger::extended_gcd(const BigInteger& other) const { return BigIntegerOps::extended_gcd(*this, other); }
inline int BigInteger::jacobi(const BigInteger& n) const { return BigIntegerOps::jacobi(*this, n); }

// 字面量
inline BigInteger operator""_bi(const char* str, size_t) {
    return BigInteger(str);
}

// --------------------------------------------------------------------------
// 全局工具函数实现
// --------------------------------------------------------------------------

inline BigInteger random_bigint(int bits) {
    if (bits <= 0) return BigInteger("0");
    int byteCount = (bits + BASE_BITS - 1) / BASE_BITS;
    int highBits = bits % BASE_BITS;
    if (highBits == 0) highBits = BASE_BITS;

    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255); 

    std::vector<uint8_t> bytes(byteCount);
    for (int i = 0; i < byteCount; ++i) bytes[i] = static_cast<uint8_t>(dist(gen));
    
    if (highBits < BASE_BITS) bytes.back() &= ((1 << highBits) - 1);
    if (bits > 0 && bytes.back() == 0) bytes.back() |= (1 << (highBits - 1));
    return BigInteger(bytes, false);
}

inline BigInteger random_bigint_range(const BigInteger& lower, const BigInteger& upper) {
    if (lower >= upper) throw std::invalid_argument("Lower bound must be less than upper bound");
    BigInteger range = upper - lower;
    int bits = 0;
    BigInteger temp = range;
    while (temp > BigInteger(0)) { temp = BigIntegerOps::divide_by_two(temp); bits++; }
    if (bits == 0) return lower;
    
    BigInteger result;
    do { result = random_bigint(bits); } while (result >= range);
    return result + lower;
}

inline bool is_prime(const BigInteger& n, int k) {
    if (n == BigInteger("2") || n == BigInteger("3")) return true;
    if (n < BigInteger("2") || (n % BigInteger("2")).is_zero()) return false;
    
    int s = 0;
    BigInteger d = n - BigInteger("1");
    BigInteger Two("2"), One("1");
    while ((d % Two).is_zero()) { d = d / Two; s++; }
    
    for (int i = 0; i < k; i++) {
        BigInteger a = random_bigint_range(Two, n - One);
        BigInteger x = a.mod_pow(d, n);
        if (x == One || x == n - One) continue;
        bool continueOuter = false;
        for (int j = 0; j < s - 1; j++) {
            x = x.mod_multiply(x, n);
            if (x == n - One) { continueOuter = true; break; }
            if (x == One) return false;
        }
        if (continueOuter) continue;
        return false;
    }
    return true;
}

inline BigInteger random_prime(int bits, int k = 20) {
    if (bits <= 0) throw std::invalid_argument("Bits must be positive");
    if (bits == 1) return BigInteger(2);
    if (bits == 2) return BigInteger(3);
    
    while (true) {
        BigInteger candidate = random_bigint(bits);
        std::vector<uint8_t> bytes = candidate.to_bytes();
        int highBits = bits % BASE_BITS;
        if (highBits == 0) highBits = BASE_BITS;
        bytes.back() |= (1 << (highBits - 1));
        bytes[0] |= 1;
        candidate = BigInteger(bytes, false);
        
        static constexpr std::uint64_t small_primes[]{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
        bool is_composite = false;
        for (auto p : small_primes) {
            if ((candidate % BigInteger(p)).is_zero()){
	            is_composite = true; break;
            }
        }
        if (is_composite) continue;
        if (is_prime(candidate, k)) return candidate;
    }
}

inline BigInteger chinese_remainder_theorem(const std::vector<BigInteger>& remainders, const std::vector<BigInteger>& mods) {
    if (remainders.size() != mods.size() || remainders.empty()) throw std::invalid_argument("Invalid input for CRT");
    BigInteger mod_product = mods[0];
    for (size_t i = 1; i < mods.size(); i++) mod_product = mod_product * mods[i];
    
    BigInteger result("0");
    for (size_t i = 0; i < mods.size(); i++) {
        BigInteger Mi = mod_product / mods[i];
        BigInteger Mi_inv = Mi.mod_inverse(mods[i]);
        BigInteger term = (remainders[i] * Mi) % mod_product;
        term = (term * Mi_inv) % mod_product;
        result = (result + term) % mod_product;
    }
    return result;
}

} // namespace bigint

static_assert(crypto_integer<bigint::BigInteger>);