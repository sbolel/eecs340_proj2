#include "contimeout.h"


void Mapping::computeEstimatedRTT(const Time& sampleRTT)
{
	if((double)estimatedRTT == 0){
		estimatedRTT = sampleRTT;
	} else {
		estimatedRTT = ((1-alpha) * (double)estimatedRTT) + (alpha * (double)sampleRTT);
	}
}

void Mapping::computeDev(const Time& sampleRTT)
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

void Mapping::computeTimeout()
{
	if(devRTT < 0){
		timeout_interval = 1;
	} else {
		timeout_interval = (double)estimatedRTT + 4*devRTT;
	}
}

void Mapping::updateEstimatedRTT(const Time& sampleRTT)
{
	computeEstimatedRTT(sampleRTT);
	computeDev(sampleRTT);
}