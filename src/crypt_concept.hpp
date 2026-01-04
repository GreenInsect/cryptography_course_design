#pragma once

#include <concepts>


// 约束 T 必须支持基本的算术运算 (模拟 Regular 概念)
template<typename T>
concept crypto_integer = requires(T a, T b) {
	requires std::convertible_to<unsigned, T>;
	requires std::convertible_to<int, T>;
	requires std::regular<T>;

	{ a + b } -> std::convertible_to<T>;
	{ a - b } -> std::convertible_to<T>;
	{ a * b } -> std::convertible_to<T>;
	{ a / b } -> std::convertible_to<T>;
	{ a % b } -> std::convertible_to<T>;

	//按c++标准应该是boolean testable，不过这个场合可以加强限制
	{ a == b } -> std::convertible_to<bool>;

	{ a & b } -> std::convertible_to<T>;
	{ a | b } -> std::convertible_to<T>;
	{ a ^ b } -> std::convertible_to<T>;
	{ ~a } -> std::convertible_to<T>;
	{ a << 1 } -> std::convertible_to<T>;
	{ a >> 1 } -> std::convertible_to<T>;
	T(0);

};