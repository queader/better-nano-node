#pragma once

#include <nano/lib/locks.hpp>
#include <nano/lib/numbers.hpp>
#include <nano/node/bucketing.hpp>
#include <nano/node/fwd.hpp>
#include <nano/secure/common.hpp>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>

namespace mi = boost::multi_index;

namespace nano
{
class bounded_backlog_config
{
public:
	size_t max_backlog{ 100000 };
	double overfill_factor{ 1.5 };
	size_t batch_size{ 128 };
};

class bounded_backlog
{
public:
	bounded_backlog (bounded_backlog_config const &, nano::node &, nano::ledger &, nano::bucketing &, nano::backlog_scan &, nano::block_processor &, nano::stats &, nano::logger &);
	~bounded_backlog ();

	void start ();
	void stop ();

	bool update (nano::secure::transaction const &, nano::account const &);
	bool activate (nano::secure::transaction const &, nano::account const &, nano::account_info const &, nano::confirmation_height_info const &);
	bool erase (nano::secure::transaction const &, nano::account const &);

	uint64_t backlog_size () const;

	nano::container_info container_info () const;

private: // Dependencies
	bounded_backlog_config const & config;
	nano::node & node;
	nano::ledger & ledger;
	nano::bucketing & bucketing;
	nano::backlog_scan & backlog_scan;
	nano::block_processor & block_processor;
	nano::stats & stats;
	nano::logger & logger;

private:
	using rollback_target = std::pair<nano::account, nano::block_hash>;

	bool predicate () const;
	void run ();
	void perform_rollbacks (std::deque<rollback_target> const & targets);
	std::deque<rollback_target> gather_targets () const;
	bool should_rollback (nano::block_hash const &) const;

	nano::amount block_priority_balance (nano::secure::transaction const &, nano::block const &) const;
	nano::priority_timestamp block_priority_timestamp (nano::secure::transaction const &, nano::block const &) const;

private:
	struct key
	{
		nano::bucket_index bucket;
		nano::priority_timestamp priority;

		auto operator<=> (key const &) const = default;
	};

	struct entry
	{
		nano::account account;
		nano::bucket_index bucket;
		nano::priority_timestamp priority;
		nano::block_hash head;
		uint64_t unconfirmed;

		bounded_backlog::key key () const
		{
			return { bucket, priority };
		}
	};

	// clang-format off
	class tag_account {};
	class tag_key {};

	using ordered_accounts = boost::multi_index_container<entry,
	mi::indexed_by<
		mi::hashed_unique<mi::tag<tag_account>,
			mi::member<entry, nano::account, &entry::account>>,
		mi::ordered_non_unique<mi::tag<tag_key>,
				mi::const_mem_fun<entry, key, &entry::key>, std::greater<>> // DESC order
	>>;
	// clang-format on

	struct bucket
	{
	};

	// nano::buckets<ordered_accounts> buckets;

	ordered_accounts accounts;

	// Keep track of the backlog size in number of unconfirmed blocks
	std::atomic<uint64_t> backlog_counter{ 0 };

private:
	std::atomic<bool> stopped{ false };
	nano::condition_variable condition;
	mutable nano::mutex mutex;
	std::thread thread;
};
}