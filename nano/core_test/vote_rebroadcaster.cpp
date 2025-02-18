#include <nano/lib/numbers.hpp>
#include <nano/node/rep_tiers.hpp>
#include <nano/node/vote_rebroadcaster.hpp>
#include <nano/secure/vote.hpp>
#include <nano/test_common/testutil.hpp>

#include <gtest/gtest.h>

#include <chrono>

using namespace std::chrono_literals;

namespace
{
struct test_context
{
	nano::vote_rebroadcaster_config config;
	nano::vote_rebroadcaster_index index;

	explicit test_context (nano::vote_rebroadcaster_config config_a = {}) :
		config{ config_a },
		index{ config }
	{
	}
};
}

TEST (vote_rebroadcaster_index, construction)
{
	test_context ctx{};
	auto & index = ctx.index;
	ASSERT_EQ (index.representatives_count (), 0);
	ASSERT_EQ (index.total_history (), 0);
	ASSERT_EQ (index.total_hashes (), 0);
}

TEST (vote_rebroadcaster_index, basic_vote_tracking)
{
	test_context ctx{};
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };
	auto vote = nano::test::make_vote (key, hashes);

	auto result = index.check_and_record (vote, nano::uint128_t{ 100 }, now);

	ASSERT_EQ (result, nano::vote_rebroadcaster_index::result::ok);
	ASSERT_EQ (index.representatives_count (), 1);
	ASSERT_EQ (index.total_history (), 1);
	ASSERT_EQ (index.total_hashes (), 1);
	ASSERT_TRUE (index.contains_representative (key.pub));
	ASSERT_TRUE (index.contains_block (key.pub, hashes[0]));
}

TEST (vote_rebroadcaster_index, duplicate_vote_rejection)
{
	test_context ctx{};
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };
	auto vote = nano::test::make_vote (key, hashes);

	// First vote should be accepted
	auto result1 = index.check_and_record (vote, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result1, nano::vote_rebroadcaster_index::result::ok);

	// Same vote should be rejected
	auto result2 = index.check_and_record (vote, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result2, nano::vote_rebroadcaster_index::result::already_rebroadcasted);

	// Even after time threshold
	auto result3 = index.check_and_record (vote, nano::uint128_t{ 100 }, now + 60min);
	ASSERT_EQ (result3, nano::vote_rebroadcaster_index::result::already_rebroadcasted);
}

TEST (vote_rebroadcaster_index, rebroadcast_timing)
{
	nano::vote_rebroadcaster_config config;
	config.rebroadcast_threshold = 1000ms;
	test_context ctx{ config };
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };

	// Initial vote
	auto vote1 = nano::test::make_vote (key, hashes, 1000);
	auto result1 = index.check_and_record (vote1, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result1, nano::vote_rebroadcaster_index::result::ok);

	// Try rebroadcast immediately - should be rejected
	auto vote2 = nano::test::make_vote (key, hashes, 1500);
	auto result2 = index.check_and_record (vote2, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result2, nano::vote_rebroadcaster_index::result::rebroadcast_unnecessary);

	// Try after threshold - should be accepted
	auto vote3 = nano::test::make_vote (key, hashes, 2500);
	auto result3 = index.check_and_record (vote3, nano::uint128_t{ 100 }, now + 2000ms);
	ASSERT_EQ (result3, nano::vote_rebroadcaster_index::result::ok);
}

TEST (vote_rebroadcaster_index, final_vote_override)
{
	test_context ctx{};
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };

	// Regular vote
	auto vote1 = nano::test::make_vote (key, hashes, 1000);
	auto result1 = index.check_and_record (vote1, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result1, nano::vote_rebroadcaster_index::result::ok);

	// Final vote should override timing restrictions
	auto final_vote = nano::test::make_final_vote (key, hashes);
	auto result2 = index.check_and_record (final_vote, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result2, nano::vote_rebroadcaster_index::result::ok);

	// Both vote should be kept in recent hashes index
	ASSERT_EQ (index.total_history (), 1);
	ASSERT_EQ (index.total_hashes (), 2);
	ASSERT_TRUE (index.contains_block (key.pub, hashes[0]));
	ASSERT_TRUE (index.contains_vote (vote1->full_hash ()));
	ASSERT_TRUE (index.contains_vote (final_vote->full_hash ()));
}

TEST (vote_rebroadcaster_index, representative_limit)
{
	nano::vote_rebroadcaster_config config;
	config.max_representatives = 2;
	test_context ctx{ config };
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	std::vector<nano::keypair> keys (4);
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };

	// Add first rep (weight 100)
	auto vote1 = nano::test::make_vote (keys[0], hashes);
	auto result1 = index.check_and_record (vote1, nano::uint128_t{ 100 }, now);
	ASSERT_EQ (result1, nano::vote_rebroadcaster_index::result::ok);
	ASSERT_EQ (index.representatives_count (), 1);

	// Add second rep (weight 200)
	auto vote2 = nano::test::make_vote (keys[1], hashes);
	auto result2 = index.check_and_record (vote2, nano::uint128_t{ 200 }, now);
	ASSERT_EQ (result2, nano::vote_rebroadcaster_index::result::ok);
	ASSERT_EQ (index.representatives_count (), 2);

	// Try to add third rep with lower weight - should be rejected
	auto vote3 = nano::test::make_vote (keys[2], hashes);
	auto result3 = index.check_and_record (vote3, nano::uint128_t{ 50 }, now);
	ASSERT_EQ (result3, nano::vote_rebroadcaster_index::result::representatives_full);
	ASSERT_EQ (index.representatives_count (), 2);

	// Add third rep with higher weight - should replace lowest weight
	auto vote4 = nano::test::make_vote (keys[3], hashes);
	auto result4 = index.check_and_record (vote4, nano::uint128_t{ 300 }, now);
	ASSERT_EQ (result4, nano::vote_rebroadcaster_index::result::ok);
	ASSERT_FALSE (index.contains_representative (keys[0].pub)); // Lowest weight was removed
	ASSERT_EQ (index.representatives_count (), 2);
}

TEST (vote_rebroadcaster_index, multi_hash_vote)
{
	test_context ctx{};
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;
	std::vector<nano::block_hash> hashes = {
		nano::block_hash{ 1 },
		nano::block_hash{ 2 },
		nano::block_hash{ 3 }
	};

	auto vote = nano::test::make_vote (key, hashes);
	auto result = index.check_and_record (vote, nano::uint128_t{ 100 }, now);

	ASSERT_EQ (result, nano::vote_rebroadcaster_index::result::ok);
	ASSERT_EQ (index.total_history (), 3); // One entry per hash
	for (auto const & hash : hashes)
	{
		ASSERT_TRUE (index.contains_block (key.pub, hash));
	}
}

TEST (vote_rebroadcaster_index, history_limit)
{
	nano::vote_rebroadcaster_config config;
	config.max_history = 2;
	test_context ctx{ config };
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key;

	// Add votes up to limit
	for (size_t i = 0; i < 3; i++)
	{
		std::vector<nano::block_hash> hash = { nano::block_hash{ i } };
		auto vote = nano::test::make_vote (key, hash);
		index.check_and_record (vote, nano::uint128_t{ 100 }, now);
	}

	ASSERT_EQ (index.total_history (), 2);
	ASSERT_FALSE (index.contains_block (key.pub, nano::block_hash{ 0 })); // Oldest was removed
	ASSERT_TRUE (index.contains_block (key.pub, nano::block_hash{ 1 }));
	ASSERT_TRUE (index.contains_block (key.pub, nano::block_hash{ 2 }));
}

TEST (vote_rebroadcaster_index, cleanup)
{
	test_context ctx{};
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key1;
	nano::keypair key2;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };

	// Add two reps
	auto vote1 = nano::test::make_vote (key1, hashes);
	auto vote2 = nano::test::make_vote (key2, hashes);
	index.check_and_record (vote1, nano::uint128_t{ 100 }, now);
	index.check_and_record (vote2, nano::uint128_t{ 200 }, now);

	// Cleanup with rep1 becoming non-principal
	auto cleanup_count = index.cleanup ([&key1] (nano::account const & account) {
		return std::make_pair (
		account == key1.pub ? false : true,
		account == key1.pub ? nano::uint128_t{ 0 } : nano::uint128_t{ 200 });
	});

	ASSERT_EQ (cleanup_count, 1);
	ASSERT_EQ (index.representatives_count (), 1);
	ASSERT_FALSE (index.contains_representative (key1.pub));
	ASSERT_TRUE (index.contains_representative (key2.pub));
}

TEST (vote_rebroadcaster_index, weight_updates)
{
	nano::vote_rebroadcaster_config config;
	config.max_representatives = 1;
	test_context ctx{ config };
	auto & index = ctx.index;
	auto now = std::chrono::steady_clock::now ();

	nano::keypair key1;
	nano::keypair key2;
	std::vector<nano::block_hash> hashes = { nano::block_hash{ 1 } };

	// Add rep with initial weight
	auto vote1 = nano::test::make_vote (key1, hashes);
	index.check_and_record (vote1, nano::uint128_t{ 100 }, now);

	// Update weight through cleanup
	index.cleanup ([] (nano::account const &) {
		return std::make_pair (true, nano::uint128_t{ 200 });
	});

	// Add new rep with lower weight - should be rejected due to updated weight
	auto vote2 = nano::test::make_vote (key2, hashes);
	auto result = index.check_and_record (vote2, nano::uint128_t{ 150 }, now);
	ASSERT_EQ (result, nano::vote_rebroadcaster_index::result::representatives_full);
}