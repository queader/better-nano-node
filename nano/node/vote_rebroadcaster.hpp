#pragma once

#include <nano/lib/locks.hpp>
#include <nano/lib/numbers.hpp>
#include <nano/node/fair_queue.hpp>
#include <nano/node/fwd.hpp>
#include <nano/node/wallet.hpp>
#include <nano/secure/vote.hpp>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <thread>
#include <unordered_map>

namespace mi = boost::multi_index;

namespace nano
{
class vote_rebroadcaster_config final
{
public:
	// TODO: Serde

public:
	bool enable{ true };
	size_t max_queue{ 1024 * 4 }; // Maximum number of votes to keep in queue for processing
	size_t max_history{ 1024 * 16 }; // Maximum number of recently broadcast hashes to keep per representative
	size_t max_representatives{ 100 }; // Maximum number of representatives to track rebroadcasts for
	std::chrono::milliseconds rebroadcast_threshold{ 1000 * 30 }; // Minimum amount of time between rebroadcasts for the same hash from the same representative (milliseconds)
	size_t priority_coefficient{ 2 }; // Priority coefficient for prioritizing votes from representative tiers
};

class vote_rebroadcaster final
{
public:
	vote_rebroadcaster (vote_rebroadcaster_config const &, nano::ledger &, nano::vote_router &, nano::network &, nano::wallets &, nano::rep_tiers &, nano::stats &, nano::logger &);
	~vote_rebroadcaster ();

	void start ();
	void stop ();

	bool push (std::shared_ptr<nano::vote> const &, nano::rep_tier);

	nano::container_info container_info () const;

public: // Dependencies
	vote_rebroadcaster_config const & config;
	nano::ledger & ledger;
	nano::vote_router & vote_router;
	nano::network & network;
	nano::wallets & wallets;
	nano::rep_tiers & rep_tiers;
	nano::stats & stats;
	nano::logger & logger;

private:
	void run ();
	void cleanup ();
	bool process (std::shared_ptr<nano::vote> const &);
	std::pair<std::shared_ptr<nano::vote>, nano::rep_tier> next ();

private:
	struct rebroadcast_entry
	{
		nano::block_hash block_hash;
		nano::vote_timestamp vote_timestamp;
		std::chrono::steady_clock::time_point timestamp;
	};

	// clang-format off
	class tag_sequenced {};
	class tag_vote_hash {};
	class tag_block_hash {};

	// Tracks rebroadcast history for individual block hashes
	using ordered_rebroadcasts = boost::multi_index_container<rebroadcast_entry,
    mi::indexed_by<
    	mi::sequenced<mi::tag<tag_sequenced>>,
        mi::hashed_unique<mi::tag<tag_block_hash>,
            mi::member<rebroadcast_entry, nano::block_hash, &rebroadcast_entry::block_hash>>
	>>;

	using ordered_hashes = boost::multi_index_container<nano::block_hash,
	mi::indexed_by<
		mi::sequenced<mi::tag<tag_sequenced>>,
		mi::hashed_unique<mi::tag<tag_vote_hash>,
			mi::identity<nano::block_hash>>
	>>;
	// clang-format on

	struct representative_entry
	{
		nano::account representative;
		nano::uint128_t weight;

		mutable ordered_rebroadcasts history;
		mutable ordered_hashes hashes;
	};

	// clang-format off
	class tag_account {};
	class tag_weight {};

	using ordered_representatives = boost::multi_index_container<representative_entry,
	mi::indexed_by<
		mi::sequenced<mi::tag<tag_sequenced>>,
		mi::hashed_unique<mi::tag<tag_account>,
			mi::member<representative_entry, nano::account, &representative_entry::representative>>,
		mi::ordered_non_unique<mi::tag<tag_weight>,
			mi::member<representative_entry, nano::uint128_t, &representative_entry::weight>>
	>>;
	// clang-format on

	// Queue of recently processed votes to potentially rebroadcast
	nano::fair_queue<std::shared_ptr<nano::vote>, nano::rep_tier> queue;
	std::unordered_set<nano::signature> queue_hashes; // Avoids queuing the same vote multiple times

	// Using rep tiers naturally bounds the number of possible entries to the maximum number of possible principal representatives (1000)
	nano::locked<ordered_representatives> rebroadcasts;

private:
	std::atomic<bool> non_principal{ true };
	nano::wallet_representatives reps;
	nano::interval refresh_interval;
	nano::interval cleanup_interval;

	bool stopped{ false };
	std::condition_variable condition;
	mutable std::mutex mutex;
	std::thread thread;
};
}