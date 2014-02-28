#ifndef _contimeout
#define _contimeout

#include "constate.h"
#include <deque>
#include <sys/time.h>
#include <unistd.h>

#include <iostream>
#include <typeinfo>

const double alpha = 0.125;
const double beta = 0.25;

struct ConnectionToRTTMapping {
	Connection connection;
	Time estimatedRTT;
	double devRTT;
	unsigned int seq_num; //the sequence number of the packet we are measuring RTT with
	Time time_sent; //record when we sent out the RTT measurement probe

	ConnectionToRTTMapping();
	ConnectionToRTTMapping(const Connection& c);
	ConnectionToRTTMapping(const ConnectionToRTTMapping& rhs);

	ConnectionToRTTMapping& operator=(const ConnectionToRTTMapping& rhs);

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

    double computeTimeout(const Time& sampleRTT);

    std::ostream & Print(std::ostream &os) const {
	os << "ConnectionToRTTMapping"
	   << "( connection="  		<< connection
	   << ", estimatedRTT="     << estimatedRTT
	   << ", devRTT="       	<< devRTT
	   << ", seq_num="  		<< seq_num
	   << ", time_sent="		<< time_sent
	   << ")";
	return os;
    }
    
    friend std::ostream &operator<<(std::ostream &os, const ConnectionToRTTMapping &L) {
	return L.Print(os);
    }

};

#endif