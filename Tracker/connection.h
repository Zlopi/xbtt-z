#pragma once

#include "client.h"
#include <vector>
#include <string>
#include <xbt/virtual_binary.h>

class Cserver;

class Cconnection: public Cclient, boost::noncopyable
{
public:
	Cclient::s;
	int run();
	void read(const std::string&);
	int recv();
	int send();
	virtual void process_events(int);
	int pre_select(fd_set* fd_read_set, fd_set* fd_write_set);
	int post_select(fd_set* fd_read_set, fd_set* fd_write_set);

	// TorrentPier begin
	Cconnection(Cserver*, const Csocket&, const sockaddr_storage&);
private:
	sockaddr_storage m_a;
	// TorrentPier end

	time_t m_ctime;
	int m_state;
	typedef std::vector<char> t_read_b;
	typedef std::vector<char> t_write_b;
	t_write_b m_write_b;
	t_read_b m_read_b;
	int m_r;
	int m_w;
	char* m_p;
	// X-Real-IP
	std::string m_xrealip;
	std::string m_announce;
};
