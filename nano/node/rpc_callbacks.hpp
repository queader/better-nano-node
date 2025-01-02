#pragma once

#include <nano/node/fwd.hpp>

namespace nano
{
class rpc_callbacks
{
public:
	explicit rpc_callbacks (nano::node &);

private: // Dependencies
	nano::node_config const & config;
	nano::node & node;
	nano::node_observers & observers;
	nano::ledger & ledger;
	nano::logger & logger;
	nano::stats & stats;

private:
	void setup_callbacks ();
	void do_rpc_callback (boost::asio::ip::tcp::resolver::iterator i_a, std::string const &, uint16_t, std::shared_ptr<std::string> const &, std::shared_ptr<std::string> const &, std::shared_ptr<boost::asio::ip::tcp::resolver> const &);
};
}