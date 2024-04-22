#include <nano/crypto_lib/random_pool_shuffle.hpp>
#include <nano/lib/blocks.hpp>
#include <nano/lib/threading.hpp>
#include <nano/lib/utility.hpp>
#include <nano/node/bootstrap_ascending/service.hpp>
#include <nano/node/network.hpp>
#include <nano/node/node.hpp>
#include <nano/node/telemetry.hpp>

#include <boost/format.hpp>

using namespace std::chrono_literals;

/*
 * network
 */

nano::network::network (nano::node & node, uint16_t port) :
	node{ node },
	id{ nano::network_constants::active_network },
	syn_cookies{ node.network_params.network.max_peers_per_ip, node.logger },
	resolver{ node.io_ctx },
	publish_filter{ 256 * 1024 },
	tcp_channels{ node, [this] (nano::message const & message, std::shared_ptr<nano::transport::channel> const & channel) {
					 inbound (message, channel);
				 } },
	port{ port }
{
}

nano::network::~network ()
{
	// All threads must be stopped before this destructor
	debug_assert (processing_threads.empty ());
	debug_assert (!cleanup_thread.joinable ());
	debug_assert (!keepalive_thread.joinable ());
	debug_assert (!reachout_thread.joinable ());
	debug_assert (!reachout_cached_thread.joinable ());
}

void nano::network::start ()
{
	cleanup_thread = std::thread ([this] () {
		nano::thread_role::set (nano::thread_role::name::network_cleanup);
		run_cleanup ();
	});

	keepalive_thread = std::thread ([this] () {
		nano::thread_role::set (nano::thread_role::name::network_keepalive);
		run_keepalive ();
	});

	reachout_thread = std::thread ([this] () {
		nano::thread_role::set (nano::thread_role::name::network_reachout);
		run_reachout ();
	});

	reachout_cached_thread = std::thread ([this] () {
		nano::thread_role::set (nano::thread_role::name::network_reachout);
		run_reachout_cached ();
	});

	if (!node.flags.disable_tcp_realtime)
	{
		tcp_channels.start ();

		for (std::size_t i = 0; i < node.config.network_threads; ++i)
		{
			processing_threads.emplace_back (nano::thread_attributes::get_default (), [this] () {
				nano::thread_role::set (nano::thread_role::name::packet_processing);
				run_processing ();
			});
		}
	}
}

void nano::network::stop ()
{
	{
		nano::lock_guard<nano::mutex> lock{ mutex };
		stopped = true;
	}
	condition.notify_all ();

	tcp_channels.stop ();
	resolver.cancel ();

	for (auto & thread : processing_threads)
	{
		thread.join ();
	}
	processing_threads.clear ();

	join_or_pass (keepalive_thread);
	join_or_pass (cleanup_thread);
	join_or_pass (reachout_thread);
	join_or_pass (reachout_cached_thread);

	port = 0;
}

void nano::network::run_processing ()
{
	try
	{
		// TODO: Move responsibility of packet queuing and processing to the message_processor class
		tcp_channels.process_messages ();
	}
	catch (boost::system::error_code & ec)
	{
		node.logger.critical (nano::log::type::network, "Error: {}", ec.message ());
		release_assert (false);
	}
	catch (std::error_code & ec)
	{
		node.logger.critical (nano::log::type::network, "Error: {}", ec.message ());
		release_assert (false);
	}
	catch (std::runtime_error & err)
	{
		node.logger.critical (nano::log::type::network, "Error: {}", err.what ());
		release_assert (false);
	}
	catch (...)
	{
		node.logger.critical (nano::log::type::network, "Unknown error");
		release_assert (false);
	}
}

void nano::network::run_cleanup ()
{
	nano::unique_lock<nano::mutex> lock{ mutex };
	while (!stopped)
	{
		condition.wait_for (lock, node.network_params.network.is_dev_network () ? 1s : 5s);
		if (stopped)
		{
			return;
		}
		lock.unlock ();

		node.stats.inc (nano::stat::type::network, nano::stat::detail::loop_cleanup);

		if (!node.flags.disable_connection_cleanup)
		{
			auto const cutoff = std::chrono::steady_clock::now () - node.network_params.network.cleanup_cutoff ();
			cleanup (cutoff);
		}

		auto const syn_cookie_cutoff = std::chrono::steady_clock::now () - node.network_params.network.syn_cookie_cutoff;
		syn_cookies.purge (syn_cookie_cutoff);

		lock.lock ();
	}
}

void nano::network::run_keepalive ()
{
	nano::unique_lock<nano::mutex> lock{ mutex };
	while (!stopped)
	{
		condition.wait_for (lock, node.network_params.network.keepalive_period);
		if (stopped)
		{
			return;
		}
		lock.unlock ();

		node.stats.inc (nano::stat::type::network, nano::stat::detail::loop_keepalive);

		flood_keepalive (0.75f);
		flood_keepalive_self (0.25f);

		tcp_channels.keepalive ();

		lock.lock ();
	}
}

void nano::network::run_reachout ()
{
	nano::unique_lock<nano::mutex> lock{ mutex };
	while (!stopped)
	{
		condition.wait_for (lock, node.network_params.network.merge_period);
		if (stopped)
		{
			return;
		}
		lock.unlock ();

		node.stats.inc (nano::stat::type::network, nano::stat::detail::loop_reachout);

		auto keepalive = tcp_channels.sample_keepalive ();
		if (keepalive)
		{
			for (auto const & peer : keepalive->peers)
			{
				if (stopped)
				{
					return;
				}

				node.stats.inc (nano::stat::type::network, nano::stat::detail::reachout_live);

				merge_peer (peer);

				// Throttle reachout attempts
				std::this_thread::sleep_for (node.network_params.network.merge_period);
			}
		}

		lock.lock ();
	}
}

void nano::network::run_reachout_cached ()
{
	nano::unique_lock<nano::mutex> lock{ mutex };
	while (!stopped)
	{
		condition.wait_for (lock, node.network_params.network.merge_period);
		if (stopped)
		{
			return;
		}
		lock.unlock ();

		node.stats.inc (nano::stat::type::network, nano::stat::detail::loop_reachout_cached);

		auto cached_peers = node.peer_history.peers ();
		for (auto const & peer : cached_peers)
		{
			if (stopped)
			{
				return;
			}

			node.stats.inc (nano::stat::type::network, nano::stat::detail::reachout_cached);

			merge_peer (peer);

			// Throttle reachout attempts
			std::this_thread::sleep_for (node.network_params.network.merge_period);
		}

		lock.lock ();
	}
}

void nano::network::send_keepalive (std::shared_ptr<nano::transport::channel> const & channel_a)
{
	nano::keepalive message{ node.network_params.network };
	random_fill (message.peers);
	channel_a->send (message);
}

void nano::network::send_keepalive_self (std::shared_ptr<nano::transport::channel> const & channel_a)
{
	nano::keepalive message{ node.network_params.network };
	fill_keepalive_self (message.peers);
	channel_a->send (message);
}

void nano::network::flood_message (nano::message & message_a, nano::transport::buffer_drop_policy const drop_policy_a, float const scale_a)
{
	for (auto & i : list (fanout (scale_a)))
	{
		i->send (message_a, nullptr, drop_policy_a);
	}
}

void nano::network::flood_keepalive (float const scale_a)
{
	nano::keepalive message{ node.network_params.network };
	random_fill (message.peers);
	flood_message (message, nano::transport::buffer_drop_policy::limiter, scale_a);
}

void nano::network::flood_keepalive_self (float const scale_a)
{
	nano::keepalive message{ node.network_params.network };
	fill_keepalive_self (message.peers);
	flood_message (message, nano::transport::buffer_drop_policy::limiter, scale_a);
}

void nano::network::flood_block (std::shared_ptr<nano::block> const & block_a, nano::transport::buffer_drop_policy const drop_policy_a)
{
	nano::publish message (node.network_params.network, block_a);
	flood_message (message, drop_policy_a);
}

void nano::network::flood_block_initial (std::shared_ptr<nano::block> const & block_a)
{
	nano::publish message (node.network_params.network, block_a);
	for (auto const & i : node.rep_crawler.principal_representatives ())
	{
		i.channel->send (message, nullptr, nano::transport::buffer_drop_policy::no_limiter_drop);
	}
	for (auto & i : list_non_pr (fanout (1.0)))
	{
		i->send (message, nullptr, nano::transport::buffer_drop_policy::no_limiter_drop);
	}
}

void nano::network::flood_vote (std::shared_ptr<nano::vote> const & vote_a, float scale)
{
	nano::confirm_ack message{ node.network_params.network, vote_a };
	for (auto & i : list (fanout (scale)))
	{
		i->send (message, nullptr);
	}
}

void nano::network::flood_vote_pr (std::shared_ptr<nano::vote> const & vote_a)
{
	nano::confirm_ack message{ node.network_params.network, vote_a };
	for (auto const & i : node.rep_crawler.principal_representatives ())
	{
		i.channel->send (message, nullptr, nano::transport::buffer_drop_policy::no_limiter_drop);
	}
}

void nano::network::flood_block_many (std::deque<std::shared_ptr<nano::block>> blocks_a, std::function<void ()> callback_a, unsigned delay_a)
{
	if (!blocks_a.empty ())
	{
		auto block_l (blocks_a.front ());
		blocks_a.pop_front ();
		flood_block (block_l);
		if (!blocks_a.empty ())
		{
			std::weak_ptr<nano::node> node_w (node.shared ());
			node.workers.add_timed_task (std::chrono::steady_clock::now () + std::chrono::milliseconds (delay_a + std::rand () % delay_a), [node_w, blocks (std::move (blocks_a)), callback_a, delay_a] () {
				if (auto node_l = node_w.lock ())
				{
					node_l->network.flood_block_many (std::move (blocks), callback_a, delay_a);
				}
			});
		}
		else if (callback_a)
		{
			callback_a ();
		}
	}
}

namespace
{
class network_message_visitor : public nano::message_visitor
{
public:
	network_message_visitor (nano::node & node_a, std::shared_ptr<nano::transport::channel> const & channel_a) :
		node{ node_a },
		channel{ channel_a }
	{
	}

	void keepalive (nano::keepalive const & message_a) override
	{
		// Check for special node port data
		auto peer0 (message_a.peers[0]);
		if (peer0.address () == boost::asio::ip::address_v6{} && peer0.port () != 0)
		{
			nano::endpoint new_endpoint (channel->get_tcp_endpoint ().address (), peer0.port ());
			node.network.merge_peer (new_endpoint);

			// Remember this for future forwarding to other peers
			channel->set_peering_endpoint (new_endpoint);
		}
	}

	void publish (nano::publish const & message) override
	{
		bool added = node.block_processor.add (message.block, nano::block_source::live, channel);
		if (!added)
		{
			node.network.publish_filter.clear (message.digest);
			node.stats.inc (nano::stat::type::drop, nano::stat::detail::publish, nano::stat::dir::in);
		}
	}

	void confirm_req (nano::confirm_req const & message_a) override
	{
		// Don't load nodes with disabled voting
		if (node.config.enable_voting && node.wallets.reps ().voting > 0)
		{
			if (!message_a.roots_hashes.empty ())
			{
				node.aggregator.add (channel, message_a.roots_hashes);
			}
		}
	}

	void confirm_ack (nano::confirm_ack const & message_a) override
	{
		if (!message_a.vote->account.is_zero ())
		{
			node.vote_processor.vote (message_a.vote, channel);
		}
	}

	void bulk_pull (nano::bulk_pull const &) override
	{
		debug_assert (false);
	}

	void bulk_pull_account (nano::bulk_pull_account const &) override
	{
		debug_assert (false);
	}

	void bulk_push (nano::bulk_push const &) override
	{
		debug_assert (false);
	}

	void frontier_req (nano::frontier_req const &) override
	{
		debug_assert (false);
	}

	void node_id_handshake (nano::node_id_handshake const & message_a) override
	{
		node.stats.inc (nano::stat::type::message, nano::stat::detail::node_id_handshake, nano::stat::dir::in);
	}

	void telemetry_req (nano::telemetry_req const & message_a) override
	{
		// Send an empty telemetry_ack if we do not want, just to acknowledge that we have received the message to
		// remove any timeouts on the server side waiting for a message.
		nano::telemetry_ack telemetry_ack{ node.network_params.network };
		if (!node.flags.disable_providing_telemetry_metrics)
		{
			auto telemetry_data = node.local_telemetry ();
			telemetry_ack = nano::telemetry_ack{ node.network_params.network, telemetry_data };
		}
		channel->send (telemetry_ack, nullptr, nano::transport::buffer_drop_policy::no_socket_drop);
	}

	void telemetry_ack (nano::telemetry_ack const & message_a) override
	{
		node.telemetry.process (message_a, channel);
	}

	void asc_pull_req (nano::asc_pull_req const & message) override
	{
		node.bootstrap_server.request (message, channel);
	}

	void asc_pull_ack (nano::asc_pull_ack const & message) override
	{
		node.ascendboot.process (message, channel);
	}

private:
	nano::node & node;
	std::shared_ptr<nano::transport::channel> channel;
};
}

void nano::network::process_message (nano::message const & message, std::shared_ptr<nano::transport::channel> const & channel)
{
	node.stats.inc (nano::stat::type::message, to_stat_detail (message.type ()), nano::stat::dir::in);
	node.logger.trace (nano::log::type::network_processed, to_log_detail (message.type ()), nano::log::arg{ "message", message });

	network_message_visitor visitor{ node, channel };
	message.visit (visitor);
}

void nano::network::inbound (const nano::message & message, const std::shared_ptr<nano::transport::channel> & channel)
{
	debug_assert (message.header.network == node.network_params.network.current_network);
	debug_assert (message.header.version_using >= node.network_params.network.protocol_version_min);
	process_message (message, channel);
}

// Send keepalives to all the peers we've been notified of
void nano::network::merge_peers (std::array<nano::endpoint, 8> const & peers_a)
{
	for (auto i (peers_a.begin ()), j (peers_a.end ()); i != j; ++i)
	{
		merge_peer (*i);
	}
}

void nano::network::merge_peer (nano::endpoint const & peer_a)
{
	if (track_reachout (peer_a))
	{
		node.stats.inc (nano::stat::type::network, nano::stat::detail::merge_peer);

		tcp_channels.start_tcp (peer_a);
	}
}

bool nano::network::not_a_peer (nano::endpoint const & endpoint_a, bool allow_local_peers)
{
	bool result (false);
	if (endpoint_a.address ().to_v6 ().is_unspecified ())
	{
		result = true;
	}
	else if (nano::transport::reserved_address (endpoint_a, allow_local_peers))
	{
		result = true;
	}
	else if (endpoint_a == endpoint ())
	{
		result = true;
	}
	return result;
}

bool nano::network::track_reachout (nano::endpoint const & endpoint_a)
{
	// Don't contact invalid IPs
	if (not_a_peer (endpoint_a, node.config.allow_local_peers))
	{
		return false;
	}
	return tcp_channels.track_reachout (endpoint_a);
}

std::deque<std::shared_ptr<nano::transport::channel>> nano::network::list (std::size_t count_a, uint8_t minimum_version_a, bool include_tcp_temporary_channels_a)
{
	std::deque<std::shared_ptr<nano::transport::channel>> result;
	tcp_channels.list (result, minimum_version_a, include_tcp_temporary_channels_a);
	nano::random_pool_shuffle (result.begin (), result.end ());
	if (count_a > 0 && result.size () > count_a)
	{
		result.resize (count_a, nullptr);
	}
	return result;
}

std::deque<std::shared_ptr<nano::transport::channel>> nano::network::list_non_pr (std::size_t count_a)
{
	std::deque<std::shared_ptr<nano::transport::channel>> result;
	tcp_channels.list (result);
	nano::random_pool_shuffle (result.begin (), result.end ());
	result.erase (std::remove_if (result.begin (), result.end (), [this] (std::shared_ptr<nano::transport::channel> const & channel) {
		return node.rep_crawler.is_pr (channel);
	}),
	result.end ());
	if (result.size () > count_a)
	{
		result.resize (count_a, nullptr);
	}
	return result;
}

// Simulating with sqrt_broadcast_simulate shows we only need to broadcast to sqrt(total_peers) random peers in order to successfully publish to everyone with high probability
std::size_t nano::network::fanout (float scale) const
{
	return static_cast<std::size_t> (std::ceil (scale * size_sqrt ()));
}

std::unordered_set<std::shared_ptr<nano::transport::channel>> nano::network::random_set (std::size_t count_a, uint8_t min_version_a, bool include_temporary_channels_a) const
{
	return tcp_channels.random_set (count_a, min_version_a, include_temporary_channels_a);
}

void nano::network::random_fill (std::array<nano::endpoint, 8> & target_a) const
{
	auto peers (random_set (target_a.size (), 0, false)); // Don't include channels with ephemeral remote ports
	debug_assert (peers.size () <= target_a.size ());
	auto endpoint (nano::endpoint (boost::asio::ip::address_v6{}, 0));
	debug_assert (endpoint.address ().is_v6 ());
	std::fill (target_a.begin (), target_a.end (), endpoint);
	auto j (target_a.begin ());
	for (auto i (peers.begin ()), n (peers.end ()); i != n; ++i, ++j)
	{
		debug_assert ((*i)->get_peering_endpoint ().address ().is_v6 ());
		debug_assert (j < target_a.end ());
		*j = (*i)->get_peering_endpoint ();
	}
}

void nano::network::fill_keepalive_self (std::array<nano::endpoint, 8> & target_a) const
{
	random_fill (target_a);
	// We will clobber values in index 0 and 1 and if there are only 2 nodes in the system, these are the only positions occupied
	// Move these items to index 2 and 3 so they propagate
	target_a[2] = target_a[0];
	target_a[3] = target_a[1];
	// Replace part of message with node external address or listening port
	target_a[1] = nano::endpoint (boost::asio::ip::address_v6{}, 0); // For node v19 (response channels)
	if (node.config.external_address != boost::asio::ip::address_v6{}.to_string () && node.config.external_port != 0)
	{
		target_a[0] = nano::endpoint (boost::asio::ip::make_address_v6 (node.config.external_address), node.config.external_port);
	}
	else
	{
		auto external_address (node.port_mapping.external_address ());
		if (external_address.address () != boost::asio::ip::address_v4::any ())
		{
			target_a[0] = nano::endpoint (boost::asio::ip::address_v6{}, port);
			boost::system::error_code ec;
			auto external_v6 = boost::asio::ip::make_address_v6 (external_address.address ().to_string (), ec);
			target_a[1] = nano::endpoint (external_v6, external_address.port ());
		}
		else
		{
			target_a[0] = nano::endpoint (boost::asio::ip::address_v6{}, port);
		}
	}
}

nano::tcp_endpoint nano::network::bootstrap_peer ()
{
	return tcp_channels.bootstrap_peer ();
}

std::shared_ptr<nano::transport::channel> nano::network::find_channel (nano::endpoint const & endpoint_a)
{
	return tcp_channels.find_channel (nano::transport::map_endpoint_to_tcp (endpoint_a));
}

std::shared_ptr<nano::transport::channel> nano::network::find_node_id (nano::account const & node_id_a)
{
	return tcp_channels.find_node_id (node_id_a);
}

nano::endpoint nano::network::endpoint () const
{
	return nano::endpoint (boost::asio::ip::address_v6::loopback (), port);
}

void nano::network::cleanup (std::chrono::steady_clock::time_point const & cutoff)
{
	node.logger.debug (nano::log::type::network, "Performing cleanup, cutoff: {}s", nano::log::seconds_delta (cutoff));

	tcp_channels.purge (cutoff);

	if (node.network.empty ())
	{
		disconnect_observer ();
	}
}

std::size_t nano::network::size () const
{
	return tcp_channels.size ();
}

float nano::network::size_sqrt () const
{
	return static_cast<float> (std::sqrt (size ()));
}

bool nano::network::empty () const
{
	return size () == 0;
}

void nano::network::erase (nano::transport::channel const & channel_a)
{
	auto const channel_type = channel_a.get_type ();
	if (channel_type == nano::transport::transport_type::tcp)
	{
		tcp_channels.erase (channel_a.get_tcp_endpoint ());
	}
}

void nano::network::exclude (std::shared_ptr<nano::transport::channel> const & channel)
{
	// Add to peer exclusion list
	excluded_peers.add (channel->get_tcp_endpoint ());

	// Disconnect
	erase (*channel);
}

bool nano::network::verify_handshake_response (const nano::node_id_handshake::response_payload & response, const nano::endpoint & remote_endpoint)
{
	// Prevent connection with ourselves
	if (response.node_id == node.node_id.pub)
	{
		node.stats.inc (nano::stat::type::handshake, nano::stat::detail::invalid_node_id);
		return false; // Fail
	}

	// Prevent mismatched genesis
	if (response.v2 && response.v2->genesis != node.network_params.ledger.genesis->hash ())
	{
		node.stats.inc (nano::stat::type::handshake, nano::stat::detail::invalid_genesis);
		return false; // Fail
	}

	auto cookie = syn_cookies.cookie (remote_endpoint);
	if (!cookie)
	{
		node.stats.inc (nano::stat::type::handshake, nano::stat::detail::missing_cookie);
		return false; // Fail
	}

	if (!response.validate (*cookie))
	{
		node.stats.inc (nano::stat::type::handshake, nano::stat::detail::invalid_signature);
		return false; // Fail
	}

	node.stats.inc (nano::stat::type::handshake, nano::stat::detail::ok);
	return true; // OK
}

std::optional<nano::node_id_handshake::query_payload> nano::network::prepare_handshake_query (const nano::endpoint & remote_endpoint)
{
	if (auto cookie = syn_cookies.assign (remote_endpoint); cookie)
	{
		nano::node_id_handshake::query_payload query{ *cookie };
		return query;
	}
	return std::nullopt;
}

nano::node_id_handshake::response_payload nano::network::prepare_handshake_response (const nano::node_id_handshake::query_payload & query, bool v2) const
{
	nano::node_id_handshake::response_payload response{};
	response.node_id = node.node_id.pub;
	if (v2)
	{
		nano::node_id_handshake::response_payload::v2_payload response_v2{};
		response_v2.salt = nano::random_pool::generate<uint256_union> ();
		response_v2.genesis = node.network_params.ledger.genesis->hash ();
		response.v2 = response_v2;
	}
	response.sign (query.cookie, node.node_id);
	return response;
}

/*
 * tcp_message_manager
 */

nano::tcp_message_manager::tcp_message_manager (unsigned incoming_connections_max_a) :
	max_entries (incoming_connections_max_a * nano::tcp_message_manager::max_entries_per_connection + 1)
{
	debug_assert (max_entries > 0);
}

void nano::tcp_message_manager::put_message (nano::tcp_message_item const & item_a)
{
	{
		nano::unique_lock<nano::mutex> lock{ mutex };
		while (entries.size () >= max_entries && !stopped)
		{
			producer_condition.wait (lock);
		}
		entries.push_back (item_a);
	}
	consumer_condition.notify_one ();
}

nano::tcp_message_item nano::tcp_message_manager::get_message ()
{
	nano::tcp_message_item result;
	nano::unique_lock<nano::mutex> lock{ mutex };
	while (entries.empty () && !stopped)
	{
		consumer_condition.wait (lock);
	}
	if (!entries.empty ())
	{
		result = std::move (entries.front ());
		entries.pop_front ();
	}
	else
	{
		result = nano::tcp_message_item{ nullptr, nano::tcp_endpoint (boost::asio::ip::address_v6::any (), 0), 0, nullptr };
	}
	lock.unlock ();
	producer_condition.notify_one ();
	return result;
}

void nano::tcp_message_manager::stop ()
{
	{
		nano::lock_guard<nano::mutex> lock{ mutex };
		stopped = true;
	}
	consumer_condition.notify_all ();
	producer_condition.notify_all ();
}

/*
 * syn_cookies
 */

nano::syn_cookies::syn_cookies (std::size_t max_cookies_per_ip_a, nano::logger & logger_a) :
	max_cookies_per_ip (max_cookies_per_ip_a),
	logger (logger_a)
{
}

std::optional<nano::uint256_union> nano::syn_cookies::assign (nano::endpoint const & endpoint_a)
{
	auto ip_addr (endpoint_a.address ());
	debug_assert (ip_addr.is_v6 ());
	nano::lock_guard<nano::mutex> lock{ syn_cookie_mutex };
	unsigned & ip_cookies = cookies_per_ip[ip_addr];
	std::optional<nano::uint256_union> result;
	if (ip_cookies < max_cookies_per_ip)
	{
		if (cookies.find (endpoint_a) == cookies.end ())
		{
			nano::uint256_union query;
			random_pool::generate_block (query.bytes.data (), query.bytes.size ());
			syn_cookie_info info{ query, std::chrono::steady_clock::now () };
			cookies[endpoint_a] = info;
			++ip_cookies;
			result = query;
		}
	}
	return result;
}

bool nano::syn_cookies::validate (nano::endpoint const & endpoint_a, nano::account const & node_id, nano::signature const & sig)
{
	auto ip_addr (endpoint_a.address ());
	debug_assert (ip_addr.is_v6 ());
	nano::lock_guard<nano::mutex> lock{ syn_cookie_mutex };
	auto result (true);
	auto cookie_it (cookies.find (endpoint_a));
	if (cookie_it != cookies.end () && !nano::validate_message (node_id, cookie_it->second.cookie, sig))
	{
		result = false;
		cookies.erase (cookie_it);
		unsigned & ip_cookies = cookies_per_ip[ip_addr];
		if (ip_cookies > 0)
		{
			--ip_cookies;
		}
		else
		{
			debug_assert (false && "More SYN cookies deleted than created for IP");
		}
	}
	return result;
}

void nano::syn_cookies::purge (std::chrono::steady_clock::time_point const & cutoff_a)
{
	logger.debug (nano::log::type::syn_cookies, "Purging syn cookies, cutoff: {}s", nano::log::seconds_delta (cutoff_a));

	nano::lock_guard<nano::mutex> lock{ syn_cookie_mutex };
	auto it (cookies.begin ());
	while (it != cookies.end ())
	{
		auto info (it->second);
		if (info.created_at < cutoff_a)
		{
			unsigned & per_ip = cookies_per_ip[it->first.address ()];
			if (per_ip > 0)
			{
				--per_ip;
			}
			else
			{
				debug_assert (false && "More SYN cookies deleted than created for IP");
			}
			it = cookies.erase (it);
		}
		else
		{
			++it;
		}
	}
}

std::optional<nano::uint256_union> nano::syn_cookies::cookie (const nano::endpoint & endpoint_a)
{
	auto ip_addr (endpoint_a.address ());
	debug_assert (ip_addr.is_v6 ());
	nano::lock_guard<nano::mutex> lock{ syn_cookie_mutex };
	auto cookie_it (cookies.find (endpoint_a));
	if (cookie_it != cookies.end ())
	{
		auto cookie = cookie_it->second.cookie;
		cookies.erase (cookie_it);
		unsigned & ip_cookies = cookies_per_ip[ip_addr];
		if (ip_cookies > 0)
		{
			--ip_cookies;
		}
		else
		{
			debug_assert (false && "More SYN cookies deleted than created for IP");
		}
		return cookie;
	}
	return std::nullopt;
}

std::size_t nano::syn_cookies::cookies_size ()
{
	nano::lock_guard<nano::mutex> lock{ syn_cookie_mutex };
	return cookies.size ();
}

std::unique_ptr<nano::container_info_component> nano::collect_container_info (network & network, std::string const & name)
{
	auto composite = std::make_unique<container_info_composite> (name);
	composite->add_component (network.tcp_channels.collect_container_info ("tcp_channels"));
	composite->add_component (network.syn_cookies.collect_container_info ("syn_cookies"));
	composite->add_component (network.excluded_peers.collect_container_info ("excluded_peers"));
	return composite;
}

std::unique_ptr<nano::container_info_component> nano::syn_cookies::collect_container_info (std::string const & name)
{
	std::size_t syn_cookies_count;
	std::size_t syn_cookies_per_ip_count;
	{
		nano::lock_guard<nano::mutex> syn_cookie_guard{ syn_cookie_mutex };
		syn_cookies_count = cookies.size ();
		syn_cookies_per_ip_count = cookies_per_ip.size ();
	}
	auto composite = std::make_unique<container_info_composite> (name);
	composite->add_component (std::make_unique<container_info_leaf> (container_info{ "syn_cookies", syn_cookies_count, sizeof (decltype (cookies)::value_type) }));
	composite->add_component (std::make_unique<container_info_leaf> (container_info{ "syn_cookies_per_ip", syn_cookies_per_ip_count, sizeof (decltype (cookies_per_ip)::value_type) }));
	return composite;
}
