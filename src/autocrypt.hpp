#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace crypt {
	inline constexpr std::size_t kNumStates = 32;
	inline constexpr std::size_t kAlphabetSize = 256;
	inline constexpr std::size_t kMaxStringLength = 1024;
	inline constexpr std::size_t kNumLayers = 3;

	struct complex_dfa_t {
		std::array<std::array<std::array<std::uint8_t, kAlphabetSize>, kNumStates>, kNumLayers> transitions{};
		std::array<std::array<std::uint8_t, kNumStates>, kNumLayers> output{};
		std::array<std::uint8_t, kNumLayers> initial_state{};
	};

	struct encrypted_data_t {
		std::array<std::uint8_t, kMaxStringLength> data{};
		std::size_t length{0};
	};

	struct encrypted_wdata_t {
		std::array<std::uint8_t, kMaxStringLength * 2> data{};
		std::size_t length{0};
	};

	namespace detail {
		using fnv1a64_t = std::uint64_t;
		inline constexpr std::uint64_t kFnvOffsetBasis64 = 0xcbf29ce484222325;
		inline constexpr std::uint64_t kFnvPrime64 = 0x100000001b3;
		__forceinline constexpr auto fnv1a64 (const char* data, const std::size_t size) noexcept -> fnv1a64_t {
			fnv1a64_t hash = kFnvOffsetBasis64;
			for (std::size_t idx = 0; idx < size; ++idx) {
				hash ^= data [idx];
				hash *= kFnvPrime64;
			}

			return hash;
		}

		constexpr auto rotate_left_8 (const std::uint8_t value, const std::uint32_t shift) noexcept -> std::uint8_t {
			const std::uint32_t n = shift & 0x7;
			return static_cast<std::uint8_t> ((value << n) | (value >> (8 - n)));
		}

		constexpr auto enhanced_magic_hash (std::uint8_t value) noexcept -> std::uint8_t {
			value ^= 0xA5;
			value = rotate_left_8 (value, 3);
			value ^= 0x5A;
			value = static_cast<std::uint8_t> (value * 0x2D);
			value ^= (value >> 4);
			value = rotate_left_8 (value, 5);
			value ^= 0xC3;
			return value;
		}

		consteval auto advanced_bit_scramble (std::uint8_t value) noexcept -> std::uint8_t {
			value = static_cast<std::uint8_t> (value * 0x67);
			value ^= 0x3C;
			value = static_cast<std::uint8_t> (((value & 0x0F) << 4) | ((value & 0xF0) >> 4));
			value ^= 0xB4;
			value = static_cast<std::uint8_t> (value * 0x9D);
			value ^= (value >> 3);
			return value;
		}

		consteval auto mba_obfuscate (std::uint32_t value) noexcept -> std::uint32_t {
			value = (value << 13) | (value >> 19);
			value ^= 0xAAAAAAAA;
			value = (value << 7) | (value >> 25);
			value ^= 0x55555555;
			value = (value << 17) | (value >> 15);
			value ^= 0xA5A5A5A5;
			return value;
		}

		consteval auto strlen_consteval (const char* str) noexcept -> std::size_t {
			std::size_t len = 0;
			while (str [len] != '\0')
				++len;
			return len;
		}

		consteval auto random_symbol (const std::uint32_t hash, const std::size_t index) noexcept -> char {
			const std::uint32_t mixed = hash ^ (hash >> 16) ^ (index * 0x9E3779B9);
			return static_cast<char> (mixed & 0xFF);
		}

		template <std::size_t N>
		consteval auto generate_random_key (const char* file, const int line) noexcept -> std::array<char, N> {
			std::array<char, N> key{};
			const auto hash = fnv1a64 (file, strlen_consteval (file)) ^ static_cast<std::uint32_t> (line);

			for (std::size_t i = 0; i < N; ++i)
				key [i] = random_symbol (hash, i);

			return key;
		}
	} // namespace detail

	consteval auto generate_complex_dfa (const std::string_view key) noexcept -> complex_dfa_t {
		complex_dfa_t dfa{};

		std::array<std::uint32_t, kNumLayers> layer_keys{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer) {
			auto layer_hash = detail::fnv1a64 (key.data (), key.size ()) ^ static_cast<std::uint32_t> (layer * 0x9E3779B9);
			layer_keys [layer] = detail::mba_obfuscate (layer_hash);
		}

		for (std::size_t layer = 0; layer < kNumLayers; ++layer) {
			const std::uint32_t layer_key = layer_keys [layer];

			dfa.initial_state [layer] = static_cast<std::uint8_t> (layer_key % kNumStates);

			for (std::size_t state = 0; state < kNumStates; ++state) {
				const std::uint8_t output_byte = detail::enhanced_magic_hash (
					static_cast<std::uint8_t> (state ^ (layer_key >> 8)));
				dfa.output [layer][state] = output_byte;

				for (std::size_t symbol = 0; symbol < kAlphabetSize; ++symbol) {
					const std::uint8_t scrambled = detail::advanced_bit_scramble (
						static_cast<std::uint8_t> (state ^ symbol ^ (layer_key & 0xFF)));
					dfa.transitions [layer][state][symbol] = scrambled % kNumStates;
				}
			}
		}

		return dfa;
	}

	consteval auto encrypt_string (const std::string_view input, const complex_dfa_t& dfa) noexcept -> encrypted_data_t {
		encrypted_data_t result{};
		result.length = input.size ();

		if (result.length > kMaxStringLength)
			result.length = kMaxStringLength;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < result.length; ++i) {
			auto symbol = static_cast<std::uint8_t> (input [i]);

			for (std::size_t layer = 0; layer < kNumLayers; ++layer) {
				const std::uint8_t current_state = states [layer];

				const std::uint8_t output = dfa.output [layer][current_state];
				const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> (i ^ layer));

				symbol ^= output ^ counter_mask;
				states [layer] = dfa.transitions [layer][current_state][symbol];
			}

			result.data [i] = symbol;
		}

		return result;
	}

	__declspec (noinline) inline auto decrypt_string_runtime (const encrypted_data_t& input, const complex_dfa_t& dfa) noexcept -> std::array<char, kMaxStringLength> {
		std::array<char, kMaxStringLength> result{};

		if (input.length > kMaxStringLength)
			return result;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < input.length; ++i) {
			std::uint8_t symbol = input.data [i];

			for (int layer = static_cast<int> (kNumLayers) - 1; layer >= 0; --layer) {
				const std::uint8_t current_state = states [layer];
				const std::uint8_t encrypted_symbol = symbol;

				const std::uint8_t output = dfa.output [layer][current_state];
				const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> (i ^ layer));

				symbol ^= output ^ counter_mask;
				states [layer] = dfa.transitions [layer][current_state][encrypted_symbol];
			}

			result [i] = static_cast<char> (symbol);
		}

		return result;
	}

	consteval auto decrypt_string (const encrypted_data_t& input, const complex_dfa_t& dfa) noexcept -> std::array<char, kMaxStringLength> {
		std::array<char, kMaxStringLength> result{};

		if (input.length > kMaxStringLength)
			return result;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < input.length; ++i) {
			std::uint8_t symbol = input.data [i];

			for (int layer = static_cast<int> (kNumLayers) - 1; layer >= 0; --layer) {
				const std::uint8_t current_state = states [layer];

				const std::uint8_t encrypted_symbol = symbol;

				const std::uint8_t output = dfa.output [layer][current_state];
				const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> (i ^ layer));

				symbol ^= output ^ counter_mask;

				states [layer] = dfa.transitions [layer][current_state][encrypted_symbol];
			}

			result [i] = static_cast<char> (symbol);
		}

		return result;
	}

	consteval auto encrypt_wstring (const std::wstring_view input, const complex_dfa_t& dfa) noexcept -> encrypted_wdata_t {
		encrypted_wdata_t result{};
		result.length = input.size ();

		if (result.length > kMaxStringLength)
			result.length = kMaxStringLength;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < result.length; ++i) {
			const auto wchar = static_cast<std::uint16_t> (input [i]);
			const std::size_t byte_idx = i * 2;

			for (std::size_t byte_offset = 0; byte_offset < 2; ++byte_offset) {
				auto symbol = static_cast<std::uint8_t> ((wchar >> (byte_offset * 8)) & 0xFF);

				for (std::size_t layer = 0; layer < kNumLayers; ++layer) {
					const std::uint8_t current_state = states [layer];
					const std::uint8_t output = dfa.output [layer][current_state];
					const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> ((byte_idx + byte_offset) ^ layer));

					symbol ^= output ^ counter_mask;
					states [layer] = dfa.transitions [layer][current_state][symbol];
				}

				result.data [byte_idx + byte_offset] = symbol;
			}
		}

		return result;
	}

	__declspec (noinline) inline auto decrypt_wstring_runtime (const encrypted_wdata_t& input, const complex_dfa_t& dfa) noexcept -> std::array<wchar_t, kMaxStringLength> {
		std::array<wchar_t, kMaxStringLength> result{};

		if (input.length > kMaxStringLength)
			return result;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < input.length; ++i) {
			const std::size_t byte_idx = i * 2;
			std::uint16_t wchar = 0;

			for (std::size_t byte_offset = 0; byte_offset < 2; ++byte_offset) {
				std::uint8_t symbol = input.data [byte_idx + byte_offset];

				for (int layer = static_cast<int> (kNumLayers) - 1; layer >= 0; --layer) {
					const std::uint8_t current_state = states [layer];
					const std::uint8_t encrypted_symbol = symbol;

					const std::uint8_t output = dfa.output [layer][current_state];
					const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> ((byte_idx + byte_offset) ^ layer));

					symbol ^= output ^ counter_mask;
					states [layer] = dfa.transitions [layer][current_state][encrypted_symbol];
				}

				wchar |= static_cast<std::uint16_t> (symbol) << (byte_offset * 8);
			}

			result [i] = static_cast<wchar_t> (wchar);
		}

		return result;
	}

	consteval auto decrypt_wstring (const encrypted_wdata_t& input, const complex_dfa_t& dfa) noexcept -> std::array<wchar_t, kMaxStringLength> {
		std::array<wchar_t, kMaxStringLength> result{};

		if (input.length > kMaxStringLength)
			return result;

		std::array<std::uint8_t, kNumLayers> states{};
		for (std::size_t layer = 0; layer < kNumLayers; ++layer)
			states [layer] = dfa.initial_state [layer];

		for (std::size_t i = 0; i < input.length; ++i) {
			const std::size_t byte_idx = i * 2;
			std::uint16_t wchar = 0;

			for (std::size_t byte_offset = 0; byte_offset < 2; ++byte_offset) {
				std::uint8_t symbol = input.data [byte_idx + byte_offset];

				for (int layer = static_cast<int> (kNumLayers) - 1; layer >= 0; --layer) {
					const std::uint8_t current_state = states [layer];
					const std::uint8_t encrypted_symbol = symbol;

					const std::uint8_t output = dfa.output [layer][current_state];
					const std::uint8_t counter_mask = detail::enhanced_magic_hash (static_cast<std::uint8_t> ((byte_idx + byte_offset) ^ layer));

					symbol ^= output ^ counter_mask;
					states [layer] = dfa.transitions [layer][current_state][encrypted_symbol];
				}

				wchar |= static_cast<std::uint16_t> (symbol) << (byte_offset * 8);
			}

			result [i] = static_cast<wchar_t> (wchar);
		}

		return result;
	}
} // namespace crypt

#define AUTOSTR(str) ([] () noexcept -> const char* {												\
	constexpr auto key = crypt::detail::generate_random_key<16> (__FILE__, __LINE__);               \
	constexpr auto dfa = crypt::generate_complex_dfa (std::string_view (key.data (), key.size ())); \
	constexpr auto encrypted = crypt::encrypt_string (str, dfa);                                    \
	static auto decrypted = crypt::decrypt_string_runtime (encrypted, dfa);                         \
	return std::string_view (decrypted.data (), encrypted.length).data ();                          \
}())																								\

#define AUTOWSTR(str) ([] () noexcept -> const wchar_t* {											\
	constexpr auto key = crypt::detail::generate_random_key<16> (__FILE__, __LINE__);               \
	constexpr auto dfa = crypt::generate_complex_dfa (std::string_view (key.data (), key.size ())); \
	constexpr auto encrypted = crypt::encrypt_wstring (str, dfa);                                   \
	static auto decrypted = crypt::decrypt_wstring_runtime (encrypted, dfa);                        \
	return std::wstring_view (decrypted.data (), encrypted.length).data ();                         \
}())																								\
