#pragma once

#include <iostream>
#include <optional>
#include <stdexcept>
#include "crypt_concept.hpp"
#include "big_integer.hpp"

template <crypto_integer T>
class math_utils {
public:
    /**
     * @brief 快速指数算法 (Square-and-Multiply)
     * 计算 (base ^ exp) % mod
     */
    static T power_mod(T base, T exp, T mod) {
        T result = 1;
        base = base % mod;

        while (exp > 0) {
            // 如果 exp 是奇数，乘上当前的 base
            if (exp % 2 == 1) {
                result = math_utils::mul_mod(result, base, mod);
            }
            // base 平方
            base = math_utils::mul_mod(base, base, mod);
            // exp 右移一位 (除以 2)
            exp = exp / 2;
        }
        return result;
    }

    /**
     * @brief 扩展欧几里得算法求模逆元
     * 计算 x 使得 (a * x) % m = 1
     * 返回 std::nullopt 如果逆元不存在
     */
    static std::optional<T> inverse_mod(T a, T m) noexcept {
        // 使用有符号大整数进行计算，处理负数情况
        // 注意：这里为了简化演示假设 T 可以转换为 long long
        // 实际大数库会有专门的 ext_gcd 实现
        long long t = 0, new_t = 1;
        long long r = static_cast<long long>(m);
        long long new_r = static_cast<long long>(a);

        while (new_r != 0) {
            long long quotient = r / new_r;

            long long temp_t = t - quotient * new_t;
            t = new_t;
            new_t = temp_t;

            long long temp_r = r - quotient * new_r;
            r = new_r;
            new_r = temp_r;
        }

        if (r > 1) return std::nullopt; // a 不可逆
        if (t < 0) t = t + static_cast<long long>(m);

        return static_cast<T>(t);
    }

    static T mul_mod(T a, T b, T m) noexcept {
        // 针对 uint64_t 使用 __int128 避免溢出
        // 如果 T 是大数库类，通常重载了 * 和 % 不需要这个 hack
        if constexpr (std::is_same_v<T, std::uint64_t>) {
        	static_assert(false, "unsupported type");
            // return static_cast<T>((static_cast<unsigned __int128>(a) * b) % m);
        } else {
            return (a * b) % m;
        }
    }
};

// --- 3. DSA 算法实现 ---

template <crypto_integer T>
struct dsa_signature {
    T r;
    T s;
};

template <crypto_integer T>
struct dsa_key {
    T x;
    T y;
};

template <crypto_integer T>
struct dsa_params {
	T p, q, g;
};

template <crypto_integer T>
class dsa_algorithm {
public:
	[[nodiscard]] dsa_algorithm() = default;

	// 构造函数：初始化公共参数 (p, q, g)
    dsa_algorithm(T p, T q, T g) : p_(std::move(p)), q_(std::move(q)), g_(std::move(g)) {}

	explicit(false) dsa_algorithm(const dsa_params<T>& params) : dsa_algorithm(params.p, params.q, params.g){

    }

	explicit(false) dsa_algorithm(dsa_params<T>&& params) : dsa_algorithm(std::move(params).p, std::move(params).q, std::move(params).g){

    }

    /**
     * @brief 生成密钥对
     * @tparam RngFunc 随机数生成函数的类型
     * @param rng 一个可调用对象，签名需为 T rng(T min, T max)，返回 [min, max] 之间的均匀随机数
     * @return 密钥对 {x, y}
     */
    template <typename RngFunc>
    dsa_key<T> generate_key_pair(RngFunc&& rng) const {
        // 随机选择私钥 x: 0 < x < q
        T x = rng(T(1), q_ - 1);

        // y = g^x mod p
        T y = math_utils<T>::power_mod(g_, x, p_);

        return {x, y};
    }

    /**
     * @brief 签名过程
     * @tparam RngFunc 随机数生成函数的类型
     * @param message_hash 消息哈希
     * @param private_key 私钥
     * @param rng 一个可调用对象，签名需为 T rng(T min, T max)
     * @return 签名 (r, s)
     */
    template <typename RngFunc>
    dsa_signature<T> sign(T message_hash, T private_key, RngFunc&& rng) const {
        T k, r, s;
        T k_inv;

        while (true) {
            k = rng(T(1), q_ - 1);

            r = math_utils<T>::power_mod(g_, k, p_) % q_;
            if (r == 0) continue;

            // 计算 k 的逆元
            auto inv_opt = math_utils<T>::inverse_mod(k, q_);
            if (!inv_opt) continue;
            k_inv = *inv_opt;

            // 计算 s
            T xr = math_utils<T>::mul_mod(private_key, r, q_);
            T h_plus_xr = (message_hash % q_ + xr) % q_;

            s = math_utils<T>::mul_mod(k_inv, h_plus_xr, q_);

            if (s != 0) break;
        }

        return {r, s};
    }

    bool verify(const T& message_hash, const dsa_signature<T>& sig, const T& public_key) const {
        T r = sig.r;
        T s = sig.s;
        if (r <= 0 || r >= q_ || s <= 0 || s >= q_) return false;
        auto w_opt = math_utils<T>::inverse_mod(s, q_);
        if (!w_opt) return false;
        T w = *w_opt;
        T u1 = math_utils<T>::mul_mod(message_hash % q_, w, q_);
        T u2 = math_utils<T>::mul_mod(r, w, q_);
        T v1 = math_utils<T>::power_mod(g_, u1, p_);
        T v2 = math_utils<T>::power_mod(public_key, u2, p_);
        T v = math_utils<T>::mul_mod(v1, v2, p_);
        v = v % q_;
        return v == r;
    }

	[[nodiscard]] const T& get_p() const{
		return p_;
	}

	[[nodiscard]] const T& get_q() const{
		return q_;
	}

	[[nodiscard]] const T& get_g() const{
		return g_;
	}


private:
    T p_;
    T q_;
    T g_;
};


template <crypto_integer IntTy>
struct dsa_verifier{
private:
	dsa_algorithm<IntTy> dsa_{};
	IntTy pk_{};

public:
	[[nodiscard]] dsa_verifier() = default;

	[[nodiscard]] dsa_verifier(const dsa_algorithm<IntTy>& dsa, const IntTy& pk)
		: dsa_(dsa),
		pk_(pk){
	}

	bool operator()(const IntTy& target, const dsa_signature<IntTy>& signature) const {
		return dsa_.verify(target, signature, pk_);
	}
};

template <crypto_integer IntTy, std::invocable<const IntTy&, const IntTy&> Rand>
struct dsa_signator{
private:
	[[no_unique_address]] Rand rand_{};

	dsa_algorithm<IntTy> dsa_{};
	dsa_key<IntTy> key_{};


public:
	[[nodiscard]] dsa_signator() = default;

	template <typename R>
	dsa_signator(const dsa_algorithm<IntTy>& dsa, const dsa_key<IntTy>& key, R&& rand)
		: rand_(std::forward<R>(rand)),
		dsa_(dsa),
		key_(key){
	}

	template <typename R>
	[[nodiscard]] dsa_signator(dsa_params<IntTy> param, R&& rand)
	: rand_(std::forward<R>(rand))
	, dsa_(std::move(param))
	, key_(dsa_.generate_key_pair(rand_)) {}

	auto operator()(const IntTy& target) const {
		return dsa_.sign(target, key_.x, rand_);
	}

	bool operator()(const IntTy& target, const dsa_signature<IntTy>& signature) const {
		return dsa_.verify(target, signature, key_.y);
	}

	[[nodiscard]] const dsa_algorithm<IntTy>& get_dsa() const noexcept {
		return dsa_;
	}

	[[nodiscard]] const dsa_key<IntTy>& get_key() const noexcept{
		return key_;
	}

	[[nodiscard]] dsa_verifier<IntTy> create_verifier() const {
		return {dsa_, key_.y};
	}
};


template <crypto_integer IntTy, std::invocable<const IntTy&, const IntTy&> Rand>
dsa_signator(dsa_params<IntTy>, Rand&&) -> dsa_signator<IntTy, std::decay_t<Rand>>;


template <crypto_integer IntTy, std::invocable<const IntTy&, const IntTy&> Rand>
dsa_signator(dsa_params<IntTy>, dsa_key<IntTy>, Rand&&) -> dsa_signator<IntTy, std::decay_t<Rand>>;


struct dsa_generator{
	using IntTy = bigint::BigInteger;

public:
	/**
	 * @brief 生成 DSA 参数
	 * @param L p 的位数 (推荐 2048)
	 * @param N q 的位数 (推荐 256)
	 */
	static dsa_params<IntTy> generate(int L = 1024, int N = 160, int k = 20){
		// if(!((L == 1024 && N == 160) || (L == 2048 && N == 224) ||
		// 	(L == 2048 && N == 256) || (L == 3072 && N == 256))){
		// 	throw std::invalid_argument("invalid parameter");
		// }

		dsa_params<IntTy> params;

		// 1. 生成 q (N bits 的素数)
		params.q = bigint::random_prime(N, k);

		// 2. 生成 p (L bits, 满足 q | p-1)
		while(true){
			// 随机生成 L 位的 candidate p
			bigint::BigInteger X = bigint::random_bigint(L);
			// 确保 p 大约是 L 位且 p = 1 (mod 2q) 以加速寻找
			bigint::BigInteger p_candidate = X - (X % (params.q * 2)) + 1;

			if(p_candidate.to_binary_string().size() < L) continue;

			// 这里的 k 轮 Miller-Rabin 保证了素性
			if(bigint::is_prime(p_candidate, k)){
				params.p = p_candidate;
				break;
			}
		}

		// 3. 生成 g (生成元)
		// g = h^((p-1)/q) mod p, 其中 1 < h < p-1 且 g > 1
		bigint::BigInteger e = (params.p - 1) / params.q;
		bigint::BigInteger h(2);
		while(true){
			params.g = bigint::BigIntegerOps::mod_pow(h, e, params.p);
			if(params.g > bigint::BigInteger(1)){
				break;
			}
			h = h + 1;
		}

		return params;
	}

	/**
	 * @brief 验证参数是否符合 FIPS 186-4 基本数学约束
	 */
	static bool verify(const dsa_params<IntTy>& params){
		if(!bigint::is_prime(params.q, 40)) return false;
		if(!bigint::is_prime(params.p, 40)) return false;
		if(!((params.p - 1) % params.q).is_zero()) return false;
		if(params.g <= 1 || bigint::BigIntegerOps::mod_pow(params.g, params.q, params.p) != 1) return false;
		return true;
	}
};
