#include <nano/lib/assert.hpp>
#include <nano/lib/interval.hpp>
#include <nano/lib/numbers_templ.hpp>
#include <nano/lib/thread_roles.hpp>
#include <nano/node/network.hpp>
#include <nano/node/rep_tiers.hpp>
#include <nano/node/vote_processor.hpp>
#include <nano/node/vote_rebroadcaster.hpp>
#include <nano/node/vote_router.hpp>
#include <nano/node/wallet.hpp>
#include <nano/secure/vote.hpp>

nano::vote_rebroadcaster::vote_rebroadcaster (nano::vote_rebroadcaster_config const & config_a, nano::vote_router & vote_router_a, nano::network & network_a, nano::wallets & wallets_a, nano::rep_tiers & rep_tiers_a, nano::stats & stats_a, nano::logger & logger_a) :
	config{ config_a },
	vote_router{ vote_router_a },
	network{ network_a },
	wallets{ wallets_a },
	rep_tiers{ rep_tiers_a },
	stats{ stats_a },
	logger{ logger_a }
{
	if (!config.enable)
	{
		return;
	}

	queue.max_size_query = [this] (auto const & origin) {
		switch (origin.source)
		{
			case nano::rep_tier::tier_3:
			case nano::rep_tier::tier_2:
			case nano::rep_tier::tier_1:
				return config.max_queue;
			case nano::rep_tier::none:
				return size_t{ 0 };
		}
		debug_assert (false);
		return size_t{ 0 };
	};

	queue.priority_query = [this] (auto const & origin) {
		switch (origin.source)
		{
			case nano::rep_tier::tier_3:
				return config.priority_coefficient * config.priority_coefficient * config.priority_coefficient;
			case nano::rep_tier::tier_2:
				return config.priority_coefficient * config.priority_coefficient;
			case nano::rep_tier::tier_1:
				return config.priority_coefficient;
			case nano::rep_tier::none:
				return size_t{ 0 };
		}
		debug_assert (false);
		return size_t{ 0 };
	};

	vote_router.vote_processed.add ([this] (std::shared_ptr<nano::vote> const & vote, nano::vote_source source, std::unordered_map<nano::block_hash, nano::vote_code> const & results) {
		bool processed = std::any_of (results.begin (), results.end (), [] (auto const & result) {
			return result.second == nano::vote_code::vote;
		});

		// Enable vote rebroadcasting only if the node does not host a representative
		// Do not rebroadcast votes from non-principal representatives
		if (processed && non_principal)
		{
			auto tier = rep_tiers.tier (vote->account);
			if (tier != nano::rep_tier::none)
			{
				push (vote, tier);
			}
		}
	});
}

nano::vote_rebroadcaster::~vote_rebroadcaster ()
{
	debug_assert (!thread.joinable ());
}

void nano::vote_rebroadcaster::start ()
{
	debug_assert (!thread.joinable ());

	if (!config.enable)
	{
		return;
	}

	thread = std::thread ([this] () {
		nano::thread_role::set (nano::thread_role::name::vote_rebroadcasting);
		run ();
	});
}

void nano::vote_rebroadcaster::stop ()
{
	{
		std::lock_guard guard{ mutex };
		stopped = true;
	}
	condition.notify_all ();
	if (thread.joinable ())
	{
		thread.join ();
	}
}

bool nano::vote_rebroadcaster::push (std::shared_ptr<nano::vote> const & vote, nano::rep_tier tier)
{
	bool added = false;
	{
		std::lock_guard guard{ mutex };

		// Do not rebroadcast local representative votes
		if (!reps.exists (vote->account) && !queue_hashes.contains (vote->signature))
		{
			added = queue.push (vote, tier);
			if (added)
			{
				queue_hashes.insert (vote->signature); // Keep track of vote signatures to avoid duplicates
			}
		}
	}
	if (added)
	{
		stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::queued);
		condition.notify_one ();
	}
	return added;
}

std::pair<std::shared_ptr<nano::vote>, nano::rep_tier> nano::vote_rebroadcaster::next ()
{
	debug_assert (!mutex.try_lock ());
	debug_assert (!queue.empty ());

	queue.periodic_update ();

	auto [vote, origin] = queue.next ();
	release_assert (vote != nullptr);
	release_assert (origin.source != nano::rep_tier::none);

	auto erased = queue_hashes.erase (vote->signature);
	debug_assert (erased == 1);

	return { vote, origin.source };
}

void nano::vote_rebroadcaster::run ()
{
	std::unique_lock lock{ mutex };
	while (!stopped)
	{
		condition.wait (lock, [&] {
			return stopped || !queue.empty ();
		});

		if (stopped)
		{
			return;
		}

		stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::loop);

		// Update local reps cache
		if (refresh_interval.elapse (15s))
		{
			stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::refresh);

			reps = wallets.reps ();
			non_principal = !reps.have_half_rep (); // Disable vote rebroadcasting if the node has a principal representative (or close to)
		}

		// Cleanup expired representatives from rebroadcasts
		if (cleanup_interval.elapse (60s))
		{
			lock.unlock ();
			cleanup ();
			lock.lock ();
		}

		float constexpr network_fanout_scale = 1.0f;

		// Wait for spare if our network traffic is too high
		if (!network.check_capacity (nano::transport::traffic_type::vote_rebroadcast, network_fanout_scale))
		{
			stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::cooldown);
			lock.unlock ();
			std::this_thread::sleep_for (100ms);
			lock.lock ();
			continue; // Wait for more capacity
		}

		if (!queue.empty ())
		{
			auto [vote, tier] = next ();

			lock.unlock ();

			bool should_rebroadcast = process (vote);
			if (should_rebroadcast)
			{
				stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::rebroadcast);
				stats.add (nano::stat::type::vote_rebroadcaster, nano::stat::detail::rebroadcast_hashes, vote->hashes.size ());
				stats.inc (nano::stat::type::vote_rebroadcaster_tier, to_stat_detail (tier));

				auto sent = network.flood_vote (vote, network_fanout_scale, /* rebroadcasted */ true);
				stats.add (nano::stat::type::vote_rebroadcaster, nano::stat::detail::sent, sent);
			}

			lock.lock ();
		}
	}
}

bool nano::vote_rebroadcaster::process (std::shared_ptr<nano::vote> const & vote)
{
	stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::process);

	auto const vote_timestamp = vote->timestamp ();
	auto const vote_hash = vote->full_hash ();

	auto rebroadcasts_l = rebroadcasts.lock ();

	auto it = rebroadcasts_l->find (vote->account);
	if (it == rebroadcasts_l->end ()) // We don't track any rebroadcasts for this rep yet
	{
		// Under normal conditions the number of principal representatives should be below this limit
		if (rebroadcasts_l->size () >= config.max_representatives)
		{
			stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::representatives_full);
			return false;
		}
		else
		{
			it = rebroadcasts_l->emplace (vote->account, ordered_rebroadcasts{}).first;
		}
	}
	release_assert (it != rebroadcasts_l->end ());

	auto & history = it->second;

	// Check if we already rebroadcasted this vote
	if (history.get<tag_vote_hash> ().contains (vote_hash))
	{
		stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::already_rebroadcasted);
		return false;
	}

	// Check if any of the hashes contained in the vote qualifies for rebroadcasting
	auto check_hash = [&] (auto const & hash) {
		if (auto existing = history.get<tag_block_hash> ().find (hash); existing != history.get<tag_block_hash> ().end ())
		{
			// Rebroadcast vote for hash if the previous rebroadcast is older than the threshold
			if (vote_timestamp > add_sat (existing->vote_timestamp, config.rebroadcast_threshold))
			{
				return true;
			}
			// Or if rep switched to final vote
			if (nano::vote::is_final_timestamp (vote_timestamp) && vote_timestamp > existing->vote_timestamp)
			{
				return true;
			}
			return false;
		}
		else
		{
			// Block hash not seen before, rebroadcast
			return true;
		}
	};

	bool should_rebroadcast = std::any_of (vote->hashes.begin (), vote->hashes.end (), check_hash);
	if (!should_rebroadcast)
	{
		stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::rebroadcast_unnecessary);
		return false;
	}

	// Update the history with the new vote info
	for (auto const & hash : vote->hashes)
	{
		if (auto existing = history.get<tag_block_hash> ().find (hash); existing != history.get<tag_block_hash> ().end ())
		{
			history.get<tag_block_hash> ().modify (existing, [&] (auto & entry) {
				entry.vote_timestamp = vote_timestamp;
				entry.vote_hash = vote_hash;
			});
		}
		else
		{
			history.get<tag_block_hash> ().emplace (rebroadcast_entry{ vote_hash, hash, vote_timestamp });
		}
	}

	while (history.size () > config.max_history)
	{
		history.pop_front (); // Remove the oldest entry
	}

	return true; // Rebroadcast the vote
}

void nano::vote_rebroadcaster::cleanup ()
{
	stats.inc (nano::stat::type::vote_rebroadcaster, nano::stat::detail::cleanup);

	auto rebroadcasts_l = rebroadcasts.lock ();

	// Remove entries for accounts that are no longer principal representatives
	auto erased_accounts = erase_if (*rebroadcasts_l, [this] (auto const & entry) {
		auto const & [account, rebroadcasts] = entry;
		return rep_tiers.tier (account) == nano::rep_tier::none;
	});

	stats.add (nano::stat::type::vote_rebroadcaster, nano::stat::detail::cleanup_tiers, erased_accounts);
}

nano::container_info nano::vote_rebroadcaster::container_info () const
{
	std::lock_guard guard{ mutex };

	auto rebroadcasts_l = rebroadcasts.lock ();

	auto total_history = std::accumulate (rebroadcasts_l->begin (), rebroadcasts_l->end (), size_t{ 0 }, [] (auto total, auto const & entry) {
		return total + entry.second.size ();
	});

	nano::container_info info;
	info.add ("queue", queue.container_info ());
	info.put ("queue_total", queue.size ());
	info.put ("queue_hashes", queue_hashes.size ());
	info.put ("accounts", rebroadcasts_l->size ());
	info.put ("history", total_history);
	return info;
}