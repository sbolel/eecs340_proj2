#include "contimeout.h"

ConnectionToRTTMapping::ConnectionToRTTMapping() : connection(), estimatedRTT(0), devRTT(-1), seq_num(0), time_sent(0)
{

}
ConnectionToRTTMapping::ConnectionToRTTMapping(const Connection& c) : connection(c), estimatedRTT(0), devRTT(-1), seq_num(0), time_sent(0)
{

}
ConnectionToRTTMapping::ConnectionToRTTMapping(const ConnectionToRTTMapping& rhs) : connection(rhs.connection), estimatedRTT(rhs.estimatedRTT), devRTT(rhs.devRTT), seq_num(rhs.seq_num), time_sent(rhs.time_sent)
{

}

ConnectionToRTTMapping& ConnectionToRTTMapping::operator=(const ConnectionToRTTMapping& rhs)
{
	connection = rhs.connection;
	estimatedRTT = rhs.estimatedRTT;
	devRTT = rhs.devRTT;
	seq_num = rhs.seq_num;
	time_sent = rhs.time_sent;

	return *this;
}

void ConnectionToRTTMapping::computeEstimatedRTT(const Time& sampleRTT)
{
	if((double)estimatedRTT == 0){
		estimatedRTT = sampleRTT;
	} else {
		estimatedRTT = ((1-alpha) * (double)estimatedRTT) + (alpha * (double)sampleRTT);
	}
}

void ConnectionToRTTMapping::computeDev(const Time& sampleRTT)
{
	if(devRTT == -1){
		devRTT = ((double)sampleRTT) / 2;
	} else {
		double diff;
		if(sampleRTT < estimatedRTT) diff = (double)estimatedRTT - (double)sampleRTT;
		else diff = (double)sampleRTT - (double)estimatedRTT;
		devRTT = ((1-beta)*(double)devRTT) + (beta*diff);
	}
}

double ConnectionToRTTMapping::computeTimeout(const Time& sampleRTT)
{
	double timeout;
	computeEstimatedRTT(sampleRTT);
	computeDev(sampleRTT);
	timeout = estimatedRTT + 4*devRTT;
	return timeout;
}