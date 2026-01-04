#pragma once

//Written by He Mingxun/162320129
//Encoded with utf-8
//Encoded with utf-8
//Encoded with utf-8
//CHECK ENCODE IF THE FILE IS OPENED WITH GBK

#include <vector>
#include <cstdint>
#include <bit>

class lfsr{
public:
	[[nodiscard]] lfsr() = default;

	/**
	 * @param degree 寄存器总位数
	 * @param generator_bits 生成多项式的指数位置，低次对应低位。
	 * 例如 P(x) = 1 + x^1 + x^3，则输入 {0, 2}
	 * @param seed 初始状态 (默认视为小端序数据)
	 */
	lfsr(
		const unsigned degree,
		const std::initializer_list<int> generator_bits, const std::uint32_t seed = 0)
		: degree_(degree), gen_(0), state_(seed){
		for(const auto pos : generator_bits){
			if(static_cast<unsigned>(pos) < 32){
				gen_ |= (1U << pos);
			} else{
				throw std::invalid_argument("lfsr generator bits out of u32 range");
			}
		}

		const std::uint32_t mask = (degree_ >= 32) ? (~0U) : ((1U << degree_) - 1U);

		state_ &= mask;
		if(state_ == 0) state_ = 1U;
	}

	std::uint8_t next_bit() noexcept{
		// 1. 获取输出位：最高位 (degree_ - 1)
		const std::uint8_t output_bit = (state_ >> (degree_ - 1)) & 1U;

		// 2. 计算反馈位
		const std::uint8_t feedback = std::popcount(state_ & gen_) & 1U;

		// 3. 移位更新 (左移)
		state_ <<= 1U;

		// 4. 将反馈位放入最低位 (Bit 0)
		state_ |= feedback;

		// 5. 重新应用掩码，清除溢出 degree_ 范围的高位
		const std::uint32_t mask = (degree_ >= 32) ? ~0U : ((1U << degree_) - 1U);
		state_ &= mask;

		return output_bit;
	}

	[[nodiscard]] auto get_degree() const noexcept{ return degree_; }

	[[nodiscard]] std::uint32_t get_state() const noexcept{ return state_; }

private:
	unsigned degree_;
	std::uint32_t gen_;
	std::uint32_t state_;
};

/**
 * @brief 钟控序列生成器
 * 使用 LFSR1 控制 LFSR2 的步进
 */
class clock_controlled_generator{
private:
	lfsr lfsr1_;
	lfsr lfsr2_;

public:
	[[nodiscard]] clock_controlled_generator() = default;

	[[nodiscard]] clock_controlled_generator(const lfsr& lfsr1, const lfsr& lfsr2)
		: lfsr1_(lfsr1),
		lfsr2_(lfsr2){
	}

	clock_controlled_generator(
		std::uint32_t seed1,
		std::uint32_t seed2)
	// LFSR1: 1+x+x^3
		: lfsr1_(3, {0, 2}, seed1),
		// LFSR2: 1+x^2+x^5
		lfsr2_(5, {1, 4}, seed2){
	}

	bool next_bit() noexcept{
		if(lfsr1_.next_bit()){
			lfsr2_.next_bit();
		}

		return lfsr2_.get_state() & 1U;
	}


	[[nodiscard]] std::uint8_t next_byte() noexcept{
		std::uint8_t byte = 0;
		for(int i = 0; i < 8; ++i){
			byte |= (next_bit() << i);
		}
		return byte;
	}

	template <typename Target = std::vector<std::uint8_t>>
	Target xor_with(std::string_view input){
		Target result;
		result.reserve(input.size());

		for(const auto c : input){
			result.push_back(
				std::bit_cast<std::ranges::range_value_t<Target>>(
					static_cast<std::uint8_t>(std::bit_cast<std::uint8_t>(c) ^ next_byte())));
		}
		return result;
	}
};
