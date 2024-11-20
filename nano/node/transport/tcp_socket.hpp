#pragma once

#include <nano/boost/asio/ip/tcp.hpp>
#include <nano/boost/asio/strand.hpp>
#include <nano/lib/asio.hpp>
#include <nano/lib/async.hpp>
#include <nano/lib/locks.hpp>
#include <nano/lib/logging.hpp>
#include <nano/lib/timer.hpp>
#include <nano/node/fwd.hpp>
#include <nano/node/transport/common.hpp>
#include <nano/node/transport/fwd.hpp>

#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

namespace nano::transport
{
/** Socket class for tcp clients and newly accepted connections */
class tcp_socket final : public std::enable_shared_from_this<tcp_socket>
{
public:
	/** Construct a new (unconnected) socket */
	explicit tcp_socket (nano::node &, nano::transport::socket_endpoint = socket_endpoint::client);

	/** Construct from an existing (connected) socket */
	tcp_socket (nano::node &, asio::ip::tcp::socket, nano::transport::socket_endpoint = socket_endpoint::server);
	~tcp_socket ();

	void close ();
	void close_async ();

	nano::endpoint get_remote_endpoint () const;
	nano::endpoint get_local_endpoint () const;

	bool alive () const;

	bool has_connected () const;
	bool has_timed_out () const;

	std::chrono::steady_clock::time_point get_time_created () const;
	std::chrono::steady_clock::time_point get_time_connected () const;

public:
	asio::awaitable<std::tuple<boost::system::error_code>> co_connect (nano::endpoint const & endpoint);
	asio::awaitable<std::tuple<boost::system::error_code, size_t>> co_read (nano::shared_buffer, size_t size);
	asio::awaitable<std::tuple<boost::system::error_code, size_t>> co_write (nano::shared_buffer, size_t size);

	// Adapters for callback style code
	void async_connect (nano::endpoint const & endpoint, std::function<void (boost::system::error_code const &)> callback);
	void async_read (nano::shared_buffer, size_t size, std::function<void (boost::system::error_code const &, size_t)> callback = nullptr);
	void async_write (nano::shared_buffer, std::function<void (boost::system::error_code const &, size_t)> callback = nullptr);

private:
	asio::awaitable<std::tuple<boost::system::error_code>> co_connect_impl (nano::endpoint const & endpoint);
	asio::awaitable<std::tuple<boost::system::error_code, size_t>> co_read_impl (nano::shared_buffer, size_t size);
	asio::awaitable<std::tuple<boost::system::error_code, size_t>> co_write_impl (nano::shared_buffer, size_t size);

public: // TODO: Remove these
	nano::transport::socket_type type () const
	{
		return type_m;
	};
	void type_set (nano::transport::socket_type type)
	{
		type_m = type;
	}
	nano::transport::socket_endpoint endpoint_type () const
	{
		return endpoint_type_m;
	}

private:
	void start ();
	void stop ();

	void close_impl ();
	void close_blocking_impl ();

	asio::awaitable<void> ongoing_checkup ();
	bool checkup ();

private:
	std::weak_ptr<nano::node> node_w;
	nano::node & node;

	nano::async::strand strand;
	nano::async::task task;
	asio::ip::tcp::socket raw_socket;

	nano::endpoint remote_endpoint;
	nano::endpoint local_endpoint;

	std::atomic<bool> connected{ false };
	std::atomic<bool> closing{ false };
	std::atomic<bool> closed{ false };
	std::atomic<bool> error{ false };
	std::atomic<bool> timed_out{ false };

	std::atomic<std::chrono::steady_clock::time_point> last_receive{};
	std::atomic<std::chrono::steady_clock::time_point> last_send{};

	std::chrono::steady_clock::time_point const time_created{ std::chrono::steady_clock::now () };
	std::atomic<std::chrono::steady_clock::time_point> time_connected{};

	// Guard against conflicting concurrent async operations
	std::atomic<bool> connect_in_progress{ false };
	std::atomic<bool> read_in_progress{ false };
	std::atomic<bool> write_in_progress{ false };

private:
	socket_endpoint const endpoint_type_m;
	std::atomic<socket_type> type_m{ socket_type::undefined };

public: // Logging
	void operator() (nano::object_stream &) const;
};
}
