#pragma once

#include <nano/node/common.hpp>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index_container.hpp>

#include <atomic>
#include <string_view>
#include <thread>

namespace mi = boost::multi_index;

namespace nano
{
class node;
class stats;
class logger;
}

namespace nano::transport
{
class socket;
class tcp_server;

/**
 * Server side portion of tcp sessions. Listens for new socket connections and spawns tcp_server objects when connected.
 */
class tcp_listener final
{
public:
	tcp_listener (uint16_t port, nano::node &, std::size_t max_inbound_connections);
	~tcp_listener ();

	void start (std::function<bool (std::shared_ptr<nano::transport::socket> const &, boost::system::error_code const &)> callback);
	void stop ();

	void accept_action (boost::system::error_code const &, std::shared_ptr<nano::transport::socket> const &);

	std::size_t connection_count () const;
	nano::tcp_endpoint endpoint () const;

	std::unique_ptr<nano::container_info_component> collect_container_info (std::string const & name);

private: // Dependencies
	nano::node & node;
	nano::stats & stats;
	nano::logger & logger;

private:
	void run ();
	void run_cleanup ();
	void cleanup ();
	void wait_available_slots ();

	enum class check_result
	{
		invalid,
		accepted,
		too_many_per_ip,
		too_many_per_subnetwork,
		excluded,
	};

	check_result accept_one ();
	check_result check_limits (boost::asio::ip::address const & ip);
	size_t count_per_ip (boost::asio::ip::address const & ip) const;
	size_t count_per_subnetwork (boost::asio::ip::address const & ip) const;

	static std::string_view to_friendly_string (check_result);

private:
	void on_connection (std::function<bool (std::shared_ptr<nano::transport::socket> const &, boost::system::error_code const &)> callback_a);
	void on_connection_requeue_delayed (std::function<bool (std::shared_ptr<nano::transport::socket> const & new_connection, boost::system::error_code const &)>);

public:
	std::atomic<std::size_t> bootstrap_count{ 0 };
	std::atomic<std::size_t> realtime_count{ 0 };

private:
	struct entry
	{
		boost::asio::ip::tcp::endpoint endpoint;
		std::weak_ptr<nano::transport::socket> socket;
		std::weak_ptr<nano::transport::tcp_server> server;

		boost::asio::ip::address address () const
		{
			return endpoint.address ();
		}
	};

private:
	uint16_t const port;
	std::size_t const max_inbound_connections;

	// clang-format off
	class tag_address {};

	using ordered_connections = boost::multi_index_container<entry,
	mi::indexed_by<
		mi::hashed_non_unique<mi::tag<tag_address>,
			mi::const_mem_fun<entry, boost::asio::ip::address, &entry::address>>
	>>;
	// clang-format on
	ordered_connections connections;

	// std::unordered_map<nano::transport::tcp_server *, std::weak_ptr<nano::transport::tcp_server>> connections;
	// std::multimap<boost::asio::ip::address, std::weak_ptr<nano::transport::socket>> connections_per_address;

	boost::asio::ip::tcp::acceptor acceptor;
	boost::asio::ip::tcp::endpoint local;

	std::atomic<bool> stopped;
	nano::condition_variable condition;
	mutable nano::mutex mutex;
	std::thread thread;
	std::thread cleanup_thread;
};
}