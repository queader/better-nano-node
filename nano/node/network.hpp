#pragma once

#include <nano/node/common.hpp>
#include <nano/node/logging.hpp>
#include <nano/node/peer_exclusion.hpp>
#include <nano/node/transport/tcp.hpp>
#include <nano/node/transport/udp.hpp>
#include <nano/secure/network_filter.hpp>

#include <boost/thread/thread.hpp>

#include <memory>
#include <queue>
#include <thread>
#include <unordered_set>

namespace nano
{
class channel;
class node;
class stats;
class transaction;
class logging;

class message_buffer final
{
public:
	uint8_t * buffer{ nullptr };
	std::size_t size{ 0 };
	nano::endpoint endpoint;
};

/**
 * A circular buffer for servicing nano realtime messages.
 * This container follows a producer/consumer model where the operating system is producing data in to
 * buffers which are serviced by internal threads.
 * If buffers are not serviced fast enough they're internally dropped.
 * This container has a maximum space to hold N buffers of M size and will allocate them in round-robin order.
 * All public methods are thread-safe
 */
class message_buffer_manager final
{
public:
	// Stats - Statistics
	// Size - Size of each individual buffer
	// Count - Number of buffers to allocate
	message_buffer_manager (nano::stat & stats, std::size_t, std::size_t);
	// Return a buffer where message data can be put
	// Method will attempt to return the first free buffer
	// If there are no free buffers, an unserviced buffer will be dequeued and returned
	// Function will block if there are no free or unserviced buffers
	// Return nullptr if the container has stopped
	nano::message_buffer * allocate ();
	// Queue a buffer that has been filled with message data and notify servicing threads
	void enqueue (nano::message_buffer *);
	// Return a buffer that has been filled with message data
	// Function will block until a buffer has been added
	// Return nullptr if the container has stopped
	nano::message_buffer * dequeue ();
	// Return a buffer to the freelist after is has been serviced
	void release (nano::message_buffer *);
	// Stop container and notify waiting threads
	void stop ();

private:
	nano::stat & stats;
	nano::mutex mutex;
	nano::condition_variable condition;
	boost::circular_buffer<nano::message_buffer *> free;
	boost::circular_buffer<nano::message_buffer *> full;
	std::vector<uint8_t> slab;
	std::vector<nano::message_buffer> entries;
	bool stopped;
};

/*
 * Container that queues realtime network messages and schedules them for processing
 */
class message_queue final
{
public:
	static unsigned const max_entries_per_connection = 64;

public:
	explicit message_queue (unsigned incoming_connections_max_a, nano::logger &, nano::logging &);
	~message_queue();

	/*
	 * Add a new <message, reply channel> pair to queue. If full blocks until there is room for more messages.
	 */
	void put (std::unique_ptr<nano::message>, std::shared_ptr<nano::transport::channel> const &);
	/*
	 * Start `num_of_threads` message processing threads
	 */
	void start (std::size_t num_of_threads);
	/*
	 * Stop container and notify threads
	 */
	void stop ();
	/*
	 * Number of queued entries
	 */
	std::size_t size () const;

public:
	/*
	 * Should do the actual message processing, called from multiple threads
	 */
	std::function<void (nano::message const &, std::shared_ptr<nano::transport::channel> const &)> sink;
	/*
	 * Maximum number of queued entries
	 */
	const std::size_t max_entries;

private:
	using entry_t = std::pair<std::unique_ptr<nano::message>, std::shared_ptr<nano::transport::channel>>;

	/*
	 * Gets next message from queue. If empty blocks until there is message to return or processing is stopped.
	 */
	entry_t get ();
	/*
	 * Process messages until stopped
	 */
	void process_messages ();
	void process_one (std::unique_ptr<nano::message>, std::shared_ptr<nano::transport::channel> const &);
	void run ();

private: // Dependencies
	nano::logger & logger;
	nano::logging & logging;

private:
	mutable nano::mutex mutex;

	nano::condition_variable producer_condition;
	nano::condition_variable consumer_condition;
	std::deque<entry_t> entries;
	std::atomic<bool> stopped{ false };

	std::vector<std::thread> threads;
};

/**
 * Node ID cookies for node ID handshakes
 */
class syn_cookies final
{
public:
	syn_cookies (std::size_t);
	void purge (std::chrono::steady_clock::time_point const &);
	// Returns boost::none if the IP is rate capped on syn cookie requests,
	// or if the endpoint already has a syn cookie query
	boost::optional<nano::uint256_union> assign (nano::endpoint const &);
	// Returns false if valid, true if invalid (true on error convention)
	// Also removes the syn cookie from the store if valid
	bool validate (nano::endpoint const &, nano::account const &, nano::signature const &);
	std::unique_ptr<container_info_component> collect_container_info (std::string const &);
	std::size_t cookies_size ();

private:
	class syn_cookie_info final
	{
	public:
		nano::uint256_union cookie;
		std::chrono::steady_clock::time_point created_at;
	};
	mutable nano::mutex syn_cookie_mutex;
	std::unordered_map<nano::endpoint, syn_cookie_info> cookies;
	std::unordered_map<boost::asio::ip::address, unsigned> cookies_per_ip;
	std::size_t max_cookies_per_ip;
};

class network final
{
public:
	network (nano::node &, uint16_t port);
	~network ();

	nano::networks id;
	void start ();
	void stop ();
	void flood_message (nano::message &, nano::buffer_drop_policy const = nano::buffer_drop_policy::limiter, float const = 1.0f);
	void flood_keepalive (float const scale_a = 1.0f);
	void flood_keepalive_self (float const scale_a = 0.5f);
	void flood_vote (std::shared_ptr<nano::vote> const &, float scale);
	void flood_vote_pr (std::shared_ptr<nano::vote> const &);
	// Flood block to all PRs and a random selection of non-PRs
	void flood_block_initial (std::shared_ptr<nano::block> const &);
	// Flood block to a random selection of peers
	void flood_block (std::shared_ptr<nano::block> const &, nano::buffer_drop_policy const = nano::buffer_drop_policy::limiter);
	void flood_block_many (std::deque<std::shared_ptr<nano::block>>, std::function<void ()> = nullptr, unsigned = broadcast_interval_ms);
	/*
	 * Filters invalid and prohibited peers and tries to establish new connections to the not already connected peers
	 * @return number of new connection attempts made
	 */
	std::size_t merge_peers (std::vector<nano::endpoint> const & peers);
	/*
	 * Checks whether connection to that peer is allowed and tries to establish a new connection
	 * @return true if new connection was attempted, false otherwise
	 */
	bool merge_peer (nano::endpoint const &);
	void send_keepalive (std::shared_ptr<nano::transport::channel> const &);
	void send_keepalive_self (std::shared_ptr<nano::transport::channel> const &);
	void send_node_id_handshake (std::shared_ptr<nano::transport::channel> const &, boost::optional<nano::uint256_union> const & query, boost::optional<nano::uint256_union> const & respond_to);
	void send_confirm_req (std::shared_ptr<nano::transport::channel> const & channel_a, std::pair<nano::block_hash, nano::block_hash> const & hash_root_a);
	void broadcast_confirm_req (std::shared_ptr<nano::block> const &);
	void broadcast_confirm_req_base (std::shared_ptr<nano::block> const &, std::shared_ptr<std::vector<std::shared_ptr<nano::transport::channel>>> const &, unsigned, bool = false);
	void broadcast_confirm_req_batched_many (std::unordered_map<std::shared_ptr<nano::transport::channel>, std::deque<std::pair<nano::block_hash, nano::root>>>, std::function<void ()> = nullptr, unsigned = broadcast_interval_ms, bool = false);
	void broadcast_confirm_req_many (std::deque<std::pair<std::shared_ptr<nano::block>, std::shared_ptr<std::vector<std::shared_ptr<nano::transport::channel>>>>>, std::function<void ()> = nullptr, unsigned = broadcast_interval_ms);
	std::shared_ptr<nano::transport::channel> find_node_id (nano::account const &);
	std::shared_ptr<nano::transport::channel> find_channel (nano::endpoint const &);
	bool not_a_peer (nano::endpoint const &, bool);
	// Should we reach out to this endpoint with a keepalive message
	bool reachout (nano::endpoint const &, bool = false);
	std::deque<std::shared_ptr<nano::transport::channel>> list (std::size_t count, uint8_t min_version = 0);
	std::deque<std::shared_ptr<nano::transport::channel>> list_non_pr (std::size_t);
	// Desired fanout for a given scale
	std::size_t fanout (float scale = 1.0f) const;
	void random_fill (std::array<nano::endpoint, 8> &) const;
	void fill_keepalive_self (std::array<nano::endpoint, 8> &) const;
	// Note: The minimum protocol version is used after the random selection, so number of peers can be less than expected.
	std::unordered_set<std::shared_ptr<nano::transport::channel>> random_set (std::size_t count, uint8_t min_version = 0) const;
	// Get the next peer for attempting a tcp bootstrap connection
	nano::tcp_endpoint bootstrap_peer (bool = false);
	nano::endpoint endpoint ();
	void cleanup (std::chrono::steady_clock::time_point const &);
	void ongoing_cleanup ();
	// Node ID cookies cleanup
	nano::syn_cookies syn_cookies;
	void ongoing_syn_cookie_cleanup ();
	void ongoing_keepalive ();
	std::size_t size () const;
	float size_sqrt () const;
	bool empty () const;
	void erase (nano::transport::channel const &);
	void set_bandwidth_params (double, std::size_t);
	static std::string to_string (nano::networks);
	/*
	 * Processes a message. This is the place where every network message is ultimately processed.
	 */
	void inbound (nano::message const &, std::shared_ptr<nano::transport::channel> const &);

public: // Dependencies
	nano::node & node;

public:
	std::atomic<uint16_t> port{ 0 };
	nano::message_buffer_manager buffer_container;
	boost::asio::ip::udp::resolver resolver;
	nano::bandwidth_limiter limiter;
	nano::peer_exclusion excluded_peers;
	nano::message_queue queue;
	nano::network_filter publish_filter;
	nano::transport::udp_channels udp_channels;
	nano::transport::tcp_channels tcp_channels;
	std::function<void ()> disconnect_observer;
	// Called when a new channel is observed
	std::function<void (std::shared_ptr<nano::transport::channel>)> channel_observer;
	std::atomic<bool> stopped{ false };
	static unsigned const broadcast_interval_ms = 10;
	static std::size_t const buffer_size = 512;
	static std::size_t const confirm_req_hashes_max = 7;
	static std::size_t const confirm_ack_hashes_max = 12;
};

std::unique_ptr<container_info_component> collect_container_info (network & network, std::string const & name);
}
