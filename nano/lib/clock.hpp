#pragma once

#include <atomic>
#include <chrono>

namespace nano
{
class test_clock final
{
public:
	using duration = std::chrono::steady_clock::duration;
	using rep = duration::rep;
	using period = duration::period;
	using time_point = std::chrono::time_point<test_clock>;
	static constexpr bool is_steady = true;

	static time_point now () noexcept
	{
		return time_point{ std::chrono::steady_clock::now ().time_since_epoch () + duration{ global_offset } };
	}

	// Advance the clock by adding to the offset
	static void advance (duration d) noexcept
	{
		global_offset += d.count ();
	}

	// Set a specific offset from real time
	static void set_offset (duration d) noexcept
	{
		global_offset = d.count ();
	}

	// Reset the offset to zero
	static void reset () noexcept
	{
		global_offset = 0;
	}

private:
	static inline std::atomic<rep> global_offset{ 0 };
};

// using steady_clock = std::chrono::steady_clock;
using steady_clock = test_clock;
}