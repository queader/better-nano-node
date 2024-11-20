#pragma once

#include <nano/boost/asio/ip/tcp.hpp>

namespace nano
{
using endpoint = boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>;
using tcp_endpoint = endpoint; // TODO: Remove this alias
}
