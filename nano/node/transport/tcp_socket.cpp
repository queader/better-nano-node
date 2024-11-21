#include <nano/boost/asio/bind_executor.hpp>
#include <nano/boost/asio/read.hpp>
#include <nano/lib/enum_util.hpp>
#include <nano/node/node.hpp>
#include <nano/node/transport/tcp_socket.hpp>
#include <nano/node/transport/transport.hpp>

#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <memory>
#include <utility>

/*
 * socket
 */

nano::transport::tcp_socket::tcp_socket (nano::node & node_a, socket_endpoint endpoint_type_a) :
	tcp_socket{ node_a, boost::asio::ip::tcp::socket{ node_a.io_ctx }, endpoint_type_a }
{
	start ();
}

nano::transport::tcp_socket::tcp_socket (nano::node & node_a, asio::ip::tcp::socket raw_socket_a, socket_endpoint endpoint_type_a) :
	node_w{ node_a.shared () },
	node{ node_a },
	strand{ node_a.io_ctx.get_executor () },
	task{ strand },
	raw_socket{ std::move (raw_socket_a) },
	local_endpoint{ raw_socket.local_endpoint () },
	remote_endpoint{ raw_socket.remote_endpoint () },
	endpoint_type_m{ endpoint_type_a },
	connected{ true }
{
	last_send = last_receive = time_connected = std::chrono::steady_clock::now ();
	start ();
}

nano::transport::tcp_socket::~tcp_socket ()
{
	close ();
	release_assert (task.ready ());
}

void nano::transport::tcp_socket::close ()
{
	stop ();
	close_blocking_impl ();
}

void nano::transport::tcp_socket::close_async ()
{
	// Node context must be running to gracefully stop async tasks
	debug_assert (!node.io_ctx.stopped ());

	if (closing.exchange (true)) // Avoid closing the socket multiple times
	{
		return;
	}

	asio::post (strand, [this, /* lifetime guard */ this_s = shared_from_this ()] () {
		close_impl ();
	});
}

void nano::transport::tcp_socket::close_blocking_impl ()
{
	if (closed) // Avoid closing the socket multiple times
	{
		return;
	}

	// Node context must be running to gracefully stop async tasks
	debug_assert (!node.io_ctx.stopped ());
	// Ensure that we are not trying to await the task while running on the same thread / io_context
	debug_assert (!node.io_ctx.get_executor ().running_in_this_thread ());

	// Dispatch close raw socket to the strand, wait synchronously for the operation to complete
	auto fut = asio::dispatch (strand, asio::use_future ([this] () {
		close_impl ();
	}));
	fut.wait (); // Blocking call
}

void nano::transport::tcp_socket::close_impl ()
{
	debug_assert (strand.running_in_this_thread ());

	if (closed.exchange (true)) // Avoid closing the socket multiple times
	{
		return;
	}

	boost::system::error_code ec;
	raw_socket.shutdown (asio::ip::tcp::socket::shutdown_both, ec); // Best effort, ignore errors
	raw_socket.close (ec); // Best effort, ignore errors
	if (!ec)
	{
		node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::close);
		node.logger.debug (nano::log::type::tcp_socket, "Closed socket: {}", fmt::streamed (remote_endpoint));
	}
	else
	{
		node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::close_error);
		node.logger.error (nano::log::type::tcp_socket, "Closed socket, ungracefully: {} ({})", fmt::streamed (remote_endpoint), ec);
	}
}

// void nano::transport::tcp_socket::join ()
// {
// 	// Node context must be running to gracefully stop async tasks
// 	debug_assert (!node.io_ctx.stopped ());
// 	// Ensure that we are not trying to await the task while running on the same thread / io_context
// 	debug_assert (!node.io_ctx.get_executor ().running_in_this_thread ());
//
// 	stop ();
// }

void nano::transport::tcp_socket::start ()
{
	release_assert (!task.joinable ());
	task = nano::async::task (strand, ongoing_checkup ());
}

void nano::transport::tcp_socket::stop ()
{
	if (task.ongoing ())
	{
		// Node context must be running to gracefully stop async tasks
		debug_assert (!node.io_ctx.stopped ());
		// Ensure that we are not trying to await the task while running on the same thread / io_context
		debug_assert (!node.io_ctx.get_executor ().running_in_this_thread ());

		task.cancel ();
		task.join ();
	}
}

bool nano::transport::tcp_socket::alive () const
{
	return !closed && !closing;
}

bool nano::transport::tcp_socket::has_connected () const
{
	return connected;
}

bool nano::transport::tcp_socket::has_timed_out () const
{
	return timed_out;
}

asio::awaitable<void> nano::transport::tcp_socket::ongoing_checkup ()
{
	debug_assert (strand.running_in_this_thread ());
	try
	{
		while (!co_await nano::async::cancelled () && alive ())
		{
			bool healthy = checkup ();
			if (!healthy)
			{
				node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::unhealthy);
				node.logger.debug (nano::log::type::tcp_socket, "Unhealthy socket detected: {} (timed out: {})",
				fmt::streamed (remote_endpoint),
				timed_out.load ());

				close_impl ();
			}
			else
			{
				co_await nano::async::sleep_for (node.network_params.network.is_dev_network () ? 1s : 5s);
			}
		}
	}
	catch (boost::system::system_error const & ex)
	{
		// Operation aborted is expected when cancelling the acceptor
		debug_assert (ex.code () == asio::error::operation_aborted);
	}
	debug_assert (strand.running_in_this_thread ());
}

bool nano::transport::tcp_socket::checkup ()
{
	debug_assert (strand.running_in_this_thread ());

	auto const now = std::chrono::steady_clock::now ();

	if (connected)
	{
		if (!raw_socket.is_open ())
		{
			node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::already_closed);
			return false; // Bad
		}

		auto const cutoff = now - node.config.tcp.io_timeout;

		if (last_receive.load () < cutoff)
		{
			node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::timeout);
			node.stats.inc (nano::stat::type::tcp_socket_timeout, nano::stat::detail::timeout_receive);
			timed_out = true;
			return false; // Bad
		}
		if (last_send.load () < cutoff)
		{
			node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::timeout);
			node.stats.inc (nano::stat::type::tcp_socket_timeout, nano::stat::detail::timeout_send);
			timed_out = true;
			return false; // Bad
		}
	}
	else // Not connected yet
	{
		auto const cutoff = now - node.config.tcp.connect_timeout;

		if (time_created < cutoff)
		{
			node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::timeout);
			node.stats.inc (nano::stat::type::tcp_socket_timeout, nano::stat::detail::timeout_connect);
			timed_out = true;
			return false; // Bad
		}
	}

	return true; // Healthy
}

auto nano::transport::tcp_socket::co_connect (nano::endpoint const & endpoint) -> asio::awaitable<std::tuple<boost::system::error_code>>
{
	// Dispatch operation to the strand
	// TODO: This additional dispatch should not be necessary, but it is done during transition to coroutine based code
	co_return co_await asio::co_spawn (strand, co_connect_impl (endpoint), asio::use_awaitable);
}

// TODO: This is only used in tests, remove it, this creates untracked socket
auto nano::transport::tcp_socket::co_connect_impl (nano::endpoint const & endpoint) -> asio::awaitable<std::tuple<boost::system::error_code>>
{
	debug_assert (strand.running_in_this_thread ());
	debug_assert (endpoint_type () == socket_endpoint::client);
	debug_assert (!raw_socket.is_open ());
	release_assert (connect_in_progress.exchange (true) == false);

	auto result = co_await raw_socket.async_connect (endpoint, asio::as_tuple (asio::use_awaitable));
	auto const & [ec] = result;
	if (!ec)
	{
		// Best effort to get the endpoints
		boost::system::error_code ec_ignored;
		local_endpoint = raw_socket.local_endpoint (ec_ignored);
		remote_endpoint = raw_socket.remote_endpoint (ec_ignored);

		connected = true; // Mark as connected
		last_send = last_receive = time_connected = std::chrono::steady_clock::now ();

		node.stats.inc (nano::stat::type::tcp, nano::stat::detail::tcp_connect_success);
		node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::connect_success);
		node.logger.debug (nano::log::type::tcp_socket, "Successfully connected to: {} from local: {}",
		fmt::streamed (remote_endpoint),
		fmt::streamed (local_endpoint));
	}
	else
	{
		node.stats.inc (nano::stat::type::tcp, nano::stat::detail::tcp_connect_error);
		node.stats.inc (nano::stat::type::tcp_socket, nano::stat::detail::connect_error);
		node.logger.debug (nano::log::type::tcp_socket, "Failed to connect to: {} ({})",
		fmt::streamed (endpoint),
		fmt::streamed (local_endpoint),
		ec);

		error = true;
		close_impl ();
	}
	release_assert (connect_in_progress.exchange (false) == true);
	co_return result;
}

// Adapter for callback style code
void nano::transport::tcp_socket::async_connect (nano::endpoint const & endpoint, std::function<void (boost::system::error_code const &)> callback)
{
	debug_assert (callback);
	debug_assert (endpoint_type () == socket_endpoint::client);
	asio::co_spawn (strand, co_connect_impl (endpoint), [callback, /* lifetime guard */ this_s = shared_from_this ()] (std::exception_ptr const & ex, auto const & result) {
		release_assert (!ex);
		auto const & [ec] = result;
		callback (ec);
	});
}

auto nano::transport::tcp_socket::co_read (nano::shared_buffer buffer, size_t target_size) -> asio::awaitable<std::tuple<boost::system::error_code, size_t>>
{
	// Dispatch operation to the strand
	// TODO: This additional dispatch should not be necessary, but it is done during transition to coroutine based code
	co_return co_await asio::co_spawn (strand, co_read_impl (buffer, target_size), asio::use_awaitable);
}

auto nano::transport::tcp_socket::co_read_impl (nano::shared_buffer buffer, size_t target_size) -> asio::awaitable<std::tuple<boost::system::error_code, size_t>>
{
	debug_assert (strand.running_in_this_thread ());
	release_assert (target_size <= buffer->size (), "read buffer size mismatch");
	release_assert (read_in_progress.exchange (true) == false);

	auto result = co_await asio::async_read (raw_socket, asio::buffer (buffer->data (), target_size), asio::as_tuple (asio::use_awaitable));
	auto const & [ec, size_read] = result;
	if (!ec)
	{
		node.stats.add (nano::stat::type::traffic_tcp, nano::stat::detail::all, nano::stat::dir::in, size_read);
		last_receive = std::chrono::steady_clock::now ();
	}
	else
	{
		node.stats.inc (nano::stat::type::tcp, nano::stat::detail::tcp_read_error, nano::stat::dir::in);
		node.logger.debug (nano::log::type::tcp_socket, "Error reading from: {} ({})", fmt::streamed (remote_endpoint), ec);

		error = true;
		close_impl ();
	}
	release_assert (read_in_progress.exchange (false) == true);
	co_return result;
}

void nano::transport::tcp_socket::async_read (nano::shared_buffer buffer, size_t size, std::function<void (boost::system::error_code const &, size_t)> callback)
{
	debug_assert (callback);
	asio::co_spawn (strand, co_read_impl (buffer, size), [callback, /* lifetime guard */ this_s = shared_from_this ()] (std::exception_ptr const & ex, auto const & result) {
		release_assert (!ex);
		auto const & [ec, size] = result;
		callback (ec, size);
	});
}

auto nano::transport::tcp_socket::co_write (nano::shared_buffer buffer, size_t target_size) -> asio::awaitable<std::tuple<boost::system::error_code, size_t>>
{
	// Dispatch operation to the strand
	// TODO: This additional dispatch should not be necessary, but it is done during transition to coroutine based code
	co_return co_await asio::co_spawn (strand, co_write_impl (buffer, target_size), asio::use_awaitable);
}

auto nano::transport::tcp_socket::co_write_impl (nano::shared_buffer buffer, size_t target_size) -> asio::awaitable<std::tuple<boost::system::error_code, size_t>>
{
	debug_assert (strand.running_in_this_thread ());
	release_assert (target_size <= buffer->size (), "write buffer size mismatch");
	release_assert (write_in_progress.exchange (true) == false);

	auto result = co_await asio::async_write (raw_socket, asio::buffer (buffer->data (), target_size), asio::as_tuple (asio::use_awaitable));
	auto const & [ec, size_written] = result;
	if (!ec)
	{
		node.stats.add (nano::stat::type::traffic_tcp, nano::stat::detail::all, nano::stat::dir::out, size_written);
		last_send = std::chrono::steady_clock::now ();
	}
	else
	{
		node.stats.inc (nano::stat::type::tcp, nano::stat::detail::tcp_write_error, nano::stat::dir::out);
		node.logger.debug (nano::log::type::tcp_socket, "Error writing to: {} ({})", fmt::streamed (remote_endpoint), ec);

		error = true;
		close_impl ();
	}
	release_assert (write_in_progress.exchange (false) == true);
	co_return result;
}

void nano::transport::tcp_socket::async_write (nano::shared_buffer buffer, std::function<void (boost::system::error_code const &, size_t)> callback)
{
	debug_assert (callback);
	asio::co_spawn (strand, co_write_impl (buffer, buffer->size ()), [callback, /* lifetime guard */ this_s = shared_from_this ()] (std::exception_ptr const & ex, auto const & result) {
		release_assert (!ex);
		auto const & [ec, size] = result;
		callback (ec, size);
	});
}

nano::endpoint nano::transport::tcp_socket::get_remote_endpoint () const
{
	// Using cached value to avoid calling tcp_socket.remote_endpoint() which may be invalid (throw) after closing the socket
	return remote_endpoint;
}

nano::endpoint nano::transport::tcp_socket::get_local_endpoint () const
{
	// Using cached value to avoid calling tcp_socket.local_endpoint() which may be invalid (throw) after closing the socket
	return local_endpoint;
}

std::chrono::steady_clock::time_point nano::transport::tcp_socket::get_time_created () const
{
	return time_created;
}

std::chrono::steady_clock::time_point nano::transport::tcp_socket::get_time_connected () const
{
	return time_connected;
}

void nano::transport::tcp_socket::operator() (nano::object_stream & obs) const
{
	obs.write ("remote_endpoint", remote_endpoint);
	obs.write ("local_endpoint", local_endpoint);
	obs.write ("type", type_m.load ());
	obs.write ("endpoint_type", endpoint_type_m);
}

/*
 *
 */

std::string_view nano::transport::to_string (socket_type type)
{
	return nano::enum_util::name (type);
}

std::string_view nano::transport::to_string (socket_endpoint type)
{
	return nano::enum_util::name (type);
}
