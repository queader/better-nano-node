#pragma once

#include <boost/system/error_code.hpp>

#include <fmt/format.h>

template <>
struct fmt::formatter<boost::system::error_code>
{
	constexpr auto parse (format_parse_context & ctx)
	{
		return ctx.begin (); // No format specifiers supported
	}

	template <typename FormatContext>
	auto format (const boost::system::error_code & ec, FormatContext & ctx)
	{
		return fmt::format_to (ctx.out (), "{} {}:{}", ec.message (), ec.value (), ec.category ().name ());
	}
};