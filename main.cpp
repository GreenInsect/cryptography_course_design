#include <iostream>
#include <format>
#include <random>

#include "src/lsfr.hpp"
#include "src/hash_md5.hpp"
#include "src/dsa.hpp"
#include "src/big_integer.hpp"
#include "src/sha256.hpp"

void test_lfsr(std::string plaintext, std::uint32_t seed_lfsr1 = 0b001, std::uint32_t seed_lfsr2 = 0b11111){
	clock_controlled_generator generator_enc(seed_lfsr1, seed_lfsr2);

	std::cout << "--- 钟控序列生成器演示 ---\n";

	{
		//Encrypt / Decrypt
		std::cout << std::format("{:8}: {} \n", "Message", plaintext);
		auto ciphertext = generator_enc.xor_with<std::string>(plaintext);

		std::cout << std::format("{:8}: ", "Encoded");
		for (auto b : ciphertext) {
			std::cout << std::format("{:02X} ", b);
		}
		std::cout << "\n";

		clock_controlled_generator generator_dec(seed_lfsr1, seed_lfsr2);
		auto decrypted_text = generator_dec.xor_with<std::string>(ciphertext);
		std::cout << std::format("{:8}: {}\n", "Decoded", decrypted_text);
	}

	{
		//Observe
		std::cout << "\n--- 序列周期性观察 ---\n";
		clock_controlled_generator generator_period(seed_lfsr1, seed_lfsr2);

		std::cout << "前 (31 * 7) * 2 = 434 位输出流: \n";
		for(int j = 0; j < 2; ++j){
			for(int i = 0; i < 217; ++i){
				std::cout << static_cast<int>(generator_period.next_bit());
			}
			std::cout << "\n";
		}
	}
}

void test_md5() {
	// 实例化 MD5 计算器，使用 uint32_t 作为底层类型
	md5_hasher<std::uint32_t> hasher;
	std::string student_info = "[]-Nanjing University of Aeronautics and Astronautics";

	hasher.update(student_info);

	std::cout << "Input: " << student_info << "\n";
	std::cout << "MD5:   " << hasher.finalize() << "\n";
}


int test_dsa() {
	using num_type = uint32_t;

	std::mt19937 r{42424242};
	auto rand = [&]<typename T>(const T& lhs, const T& rhs){
		return std::uniform_int_distribution<T>(lhs, rhs).operator()(r);
	};


	// 使用 uint64_t 进行演示

	std::cout << "--- DSA 算法演示 ---\n";

	// 1. 设定 DSA 域参数 (为演示方便，选用较小的真实参数)
	// 真实场景下：p 约为 1024-3072 bits, q 约为 160-256 bits
	// 这里选取：
	// q = 101 (素数)
	// p = 8081 (素数, 且 p-1 = 8080 = 80 * 101, 所以 q 整除 p-1)
	// g: 找一个 h使得 g = h^((p-1)/q) mod p > 1
	// 令 h=3, (p-1)/q = 80. g = 3^80 mod 8081

	num_type q = 101;
	num_type p = 8081;
	// 预先计算好的 g
	num_type g = math_utils<num_type>::power_mod(3, (p-1)/q, p);

	std::cout << std::format("参数设置:\n p = {}\n q = {}\n g = {}\n", p, q, g);

	dsa_algorithm<num_type> dsa(p, q, g);

	// 2. 生成密钥对
	auto [priv_key, pub_key] = dsa.generate_key_pair(rand);

	std::cout << std::format("私钥 x = {}\n公钥 y = {}\n", priv_key, pub_key);

	// 3. 模拟消息哈希
	// 假设这是 "HeMingxun" 的哈希值截断后的整数表示
	num_type msg_hash = 123456789;
	std::cout << std::format("\n待签名的消息哈希 H(m) = {}\n", msg_hash);

	// 4. 签名
	std::cout << "正在签名...\n";
	auto signature = dsa.sign(msg_hash, priv_key, rand);
	std::cout << std::format("生成签名:\n r = {}\n s = {}\n", signature.r, signature.s);

	// 5. 验证成功的情况
	std::cout << "\n正在验证原始消息...\n";
	bool valid = dsa.verify(msg_hash, signature, pub_key);
	std::cout << (valid ? "[成功] 签名有效!" : "[失败] 签名无效!") << "\n";

	// 6. 验证失败的情况 (篡改消息)
	num_type fake_hash = msg_hash + 1;
	std::cout << std::format("\n正在验证被篡改的消息 (H = {})...\n", fake_hash);
	bool valid_fake = dsa.verify(fake_hash, signature, pub_key);
	std::cout << (valid_fake ? "[警告] 篡改消息验证通过!" : "[成功] 篡改消息被检测出 (验证失败)") << "\n";

	return 0;
}

void test_sha256(){

    std::cout << "--- SHA256 算法演示 ---\n";
    bigint::SHA256 sha;

    // 1. 处理字符串
    std::string hex_res = sha.hash_to_hex("hello world");
    std::cout << "hello world ->" << " SHA256: " << hex_res << std::endl;

}

using BigInt = bigint::BigInteger;

template <>
class math_utils<BigInt> {
public:
    static BigInt power_mod(const BigInt& base, const BigInt& exp, const BigInt& mod) {
        // 直接调用 BigInteger 的模幂运算
        return base.mod_pow(exp, mod);
    }

    static std::optional<BigInt> inverse_mod(const BigInt& a, const BigInt& m) {
        try {
            // BigInteger::mod_inverse 会在不存在时抛出异常
            return a.mod_inverse(m);
        } catch (...) {
            return std::nullopt;
        }
    }

    static BigInt mul_mod(const BigInt& a, const BigInt& b, const BigInt& m) {
        // BigInteger::mod_multiply 内部处理了蒙哥马利乘法等优化
        return a.mod_multiply(b, m);
    }
};


// 这是一个简化的参数生成器，用于演示
// 真实场景应遵循 FIPS 186-4 标准生成
dsa_params<BigInt> generate_dsa_parameters(int L = 512, int N = 160, int threshold = 512, int prime_k = 5, int try_count = 4096*10) {
    std::cout << "正在生成 DSA 参数 (可能需要几秒钟)..." << std::endl;

    BigInt p, g;
    BigInt one("1");
    BigInt two("2");

    // 1. 生成 N 位的素数 q
    std::cout << "  -> 生成素数 q (" << N << " bits)..." << std::flush;
	BigInt q = bigint::random_prime(N, 20);

    std::cout << " 完成" << std::endl;

    // 2. 生成 L 位的素数 p，满足 p - 1 是 q 的倍数
    // p = k * q + 1
    std::cout << "  -> 生成素数 p (" << L << " bits)..." << std::flush;
    for (int i = 0; i < try_count; ++i) {
        BigInt k = bigint::random_bigint(L - N);
        if (bigint::BigIntegerOps::is_odd(k)) k = k + one;

        BigInt p_candidate = k * q + one;

        // 简单的位数检查和素性测试
        if (p_candidate.to_binary_string().length() >= threshold) { // threshold <= L <= 1024
            if (bigint::is_prime(p_candidate, prime_k)) { // 快速检测
                p = std::move(p_candidate);
                break;
            }
        }
    }
    if (p.is_zero()) throw std::runtime_error("生成素数 P 失败，请重试");
    std::cout << " 完成" << std::endl;

    // 3. 生成生成元 g
    // g = h^((p-1)/q) mod p, 且 g > 1
    std::cout << "  -> 计算生成元 g..." << std::flush;
    BigInt h(2);
    BigInt exp = (p - one) / q;
    while (true) {
        g = h.mod_pow(exp, p);
        if (g > one) break;
        h = h + one;
    }
    std::cout << " 完成" << std::endl;

    return {p, q, g};
}

// ==========================================
// 3. 测试主逻辑
// ==========================================


void test_bigint_dsa_md5() {
    std::cout << "========================================\n";
    std::cout << "    BigInteger + MD5 + DSA 集成测试\n";
    std::cout << "========================================\n";

    // -------------------------------------------------
    // 第一步：参数生成
    // -------------------------------------------------
    // 为了演示速度，我们使用较小的参数: L=256 bits, N=64 bits
    // 生产环境通常用 L=2048/3072, N=224/256
	auto params = generate_dsa_parameters(1024, 160);

	dsa_signator sgnator{params, [](const BigInt& min, const BigInt& max) {
		return bigint::random_bigint_range(min, max);
	}};

	{
		const auto& p = sgnator.get_dsa().get_p();
    	const auto& q = sgnator.get_dsa().get_q();
    	const auto& g = sgnator.get_dsa().get_g();

    	std::cout << "\n[公共参数]:\n";
    	std::cout << "q (" << q.to_binary_string().size() << " bits) = " << q << "\n";
    	std::cout << "p (" << p.to_binary_string().size() << " bits) = " << p << "\n";
    	std::cout << "g = " << g << "\n";
	}

	{
		auto [priv_key, pub_key] = sgnator.get_key();
    	std::cout << "私钥 (x) = " << priv_key << "\n";
    	std::cout << "公钥 (y) = " << pub_key << "\n";
	}

    std::string message = "Test Message | Test Message | 1234567890+-";
    std::cout << "\n[消息处理]\n";
    std::cout << "原文: \"" << message << "\"\n";

    // 计算 MD5
    md5_hasher<std::uint32_t> hasher; // MD5 内部标准使用 uint32
    hasher.update(message);
    std::string md5_hex = hasher.finalize();
    std::cout << "MD5 Hex: " << md5_hex << "\n";

    // 将 MD5 Hex 转换为 BigInteger
    // 注意：BigInteger 构造函数支持指定进制
    BigInt msg_hash(std::as_bytes(std::span{md5_hex}));
    std::cout << "Hash(int): " << msg_hash << "\n";

    std::cout << "\n[执行签名]...\n";
    auto signature = sgnator(msg_hash);
    std::cout << "r = " << signature.r << "\n";
    std::cout << "s = " << signature.s << "\n";


	{
		std::cout << "\n[验证签名]...\n";

    	auto verifier = sgnator.create_verifier();

    	// 1. 验证正确的消息
    	bool valid_ok = verifier(msg_hash, signature);
    	std::cout << "验证原始消息: " << (valid_ok ? "PASS (成功)" : "FAIL (失败)") << "\n";

    	// 2. 验证被篡改的消息
    	BigInt fake_hash = msg_hash + BigInt("1");
    	bool valid_fake = verifier(fake_hash, signature);
    	std::cout << "验证篡改消息: " << (valid_fake ? "FAIL (错误通过)" : "PASS (成功拒绝)") << "\n";
	}
}

int main() {

//	BigInt val = bigint::BigIntegerOps::mod_pow(7, 565, 561);
//	std::cout << "7^565 % 561 = " << val.to_string() << "\n\n";
//
//	try {
//		test_bigint_dsa_md5();
//	} catch (const std::exception& e) {
//		std::cerr << "发生异常: " << e.what() << std::endl;
//	}

	// test_dsa();
	// test_md5();
	// test_lfsr("162320129-何明迅");
    test_sha256();
}