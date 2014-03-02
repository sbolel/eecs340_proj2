#ifndef _contimeout
#define _contimeout

#include "constate.h"
#include "tcpstate.h"
#include <deque>
#include <sys/time.h>
#include <unistd.h>

#include <iostream>
#include <typeinfo>

const double alpha = 0.125;
const double beta = 0.25;

struct Mapping {
    Connection connection;
    Time       timeout;
    TCPState      state;
    bool       bTmrActive;
    Time estimatedRTT;
	double devRTT;
	unsigned int seq_num; //the sequence number of the packet we are measuring RTT with
	Time time_sent; //record when we sent out the RTT measurement probe
	double timeout_interval;
	std::deque<Packet> retransmit_queue;
    
    Mapping(const Mapping &rhs) :
	connection(rhs.connection), timeout(rhs.timeout), state(rhs.state), bTmrActive(rhs.bTmrActive), estimatedRTT(rhs.estimatedRTT), devRTT(rhs.devRTT), seq_num(rhs.seq_num), time_sent(rhs.time_sent), timeout_interval(rhs.timeout_interval), retransmit_queue(rhs.retransmit_queue)
    {
    }
    
    Mapping(const Connection &c, const Time &t, const TCPState &s, const bool &b) :
	connection(c), timeout(t), state(s), bTmrActive(b), estimatedRTT(0), devRTT(-1), seq_num(0), time_sent(0), timeout_interval(-1), retransmit_queue()
    {
    }
    
    Mapping() : connection(), timeout(), state(), bTmrActive(), estimatedRTT(0), devRTT(-1), seq_num(0), time_sent(0), timeout_interval(-1), retransmit_queue()
    {
    }
    
    Mapping & operator=(const Mapping &rhs)  {
	connection = rhs.connection; 
	timeout    = rhs.timeout; 
	state      = rhs.state;
	bTmrActive = rhs.bTmrActive; 
	estimatedRTT = rhs.estimatedRTT;
	devRTT = rhs.devRTT;
	seq_num = rhs.seq_num;
	time_sent = rhs.time_sent;
	timeout_interval = rhs.timeout_interval;
	retransmit_queue = rhs.retransmit_queue;

	return *this;
    }
    
    bool MatchesSource(const Connection &rhs) const {
	return connection.MatchesSource(rhs);
    }
    
    bool MatchesDest(const Connection &rhs) const {
	return connection.MatchesDest(rhs);
    }
    
    bool MatchesProtocol(const Connection &rhs) const {
	return connection.MatchesProtocol(rhs);
    }
    
    bool Matches(const Connection &rhs) const {
	return connection.Matches(rhs);
    }

    void computeEstimatedRTT(const Time& sampleRTT);

    void computeDev(const Time& sampleRTT);

    void computeTimeout();

    void updateEstimatedRTT(const Time& sampleRTT);
    
    std::ostream & Print(std::ostream &os) const {
	os << "Mapping"
	   << "( connection="  << connection
	   << ", timeout="     << timeout
	   << ", state="       << state
	   << ", bTmrActive="  << bTmrActive
	   << ", estimatedRTT="     << estimatedRTT
	   << ", devRTT="       	<< devRTT
	   << ", seq_num="  		<< seq_num
	   << ", time_sent="		<< time_sent
	   << ", size of queue="	<< retransmit_queue.size()
	   << ")";
	return os;
    }
    
    friend std::ostream &operator<<(std::ostream &os, const Mapping &L) {
	return L.Print(os);
    }
};

class CList : public std::deque<Mapping > {
 public:
    CList(const CList &rhs) : std::deque<Mapping >(rhs) {}
    CList() {}
    
    CList::iterator FindEarliest() {
		CList::iterator ptr = this->end();
		CList::iterator i = this->begin();
		
		// No connections in list
		if(this->empty())
		    return this->end();
		
		// 1 connection in list
		if(this->size() == 1) {
		    if((*i).bTmrActive == true)
			return this->begin();
		    else {
			return this->end();
		    }
		}
		
		// More than one connection in list
		Time min=(*i).timeout;
		bool replace = !(*i).bTmrActive;
		for (; i != this->end(); ++i) {
		    if ((*i).bTmrActive == true && ((*i).timeout <= min || replace)) {
			min=(*i).timeout;
			ptr=i;
		    }
		}
		return ptr;
    }

    CList::iterator FindExactMatching(const Connection& rhs)
    {
    	Connection c;
    	for(CList::iterator i = this->begin(); i != this->end(); ++i){
    		c = i->connection;
    		if(c.src == rhs.src && c.dest == rhs.dest && c.srcport == rhs.srcport && c.destport == rhs.destport && c.protocol == rhs.protocol){
		      return i;
		    }
    	}
    	return this->end();
    }

    CList::iterator FindMatching(const Connection &rhs) {
	for ( CList::iterator i = this->begin(); i != this->end(); ++i) {
	    if ((*i).Matches(rhs)) {
		return i;
		}
	}
	return this->end();
    }
    CList::iterator FindMatchingSource(const Connection &rhs) {
	for ( CList::iterator i = this->begin(); i != this->end(); ++i) {
	    if ((*i).MatchesSource(rhs)) {
		return i;
	    }
	}
	return this->end();
    }
     CList::iterator FindMatchingDest(const Connection &rhs) {
	for ( CList::iterator i = this->begin(); i != this->end(); ++i) {
	    if ((*i).MatchesDest(rhs)) {
		return i;
	    }
	}
	return this->end();
    }
     CList::iterator FindMatchingProtocol(const Connection &rhs) {
	for ( CList::iterator i = this->begin(); i != this->end(); ++i) {
	    if ((*i).MatchesProtocol(rhs)) {
		return i;
	    }
	}
	return this->end();
    }
    
    std::ostream & Print(std::ostream &os) const {
	os << "CList(";
	for (CList::const_iterator i = this->begin(); i != this->end(); ++i) {
	    os << (*i);
	}
	os << ")";
	return os;
    }
    
    friend std::ostream &operator<<(std::ostream &os, const CList& L) {
	return L.Print(os);
    }
};



#endif