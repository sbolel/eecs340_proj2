#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <deque>
#include <cmath>

#include <iostream>

#include "Minet.h"
#include "tcpstate.h"
#include "contimeout.h"


using namespace std;
// using std::cout;
// using std::endl;
// using std::cerr;
// using std::string;


CList clist;
MinetHandle mux;
MinetHandle sock;


int sendUp(Connection& c, srrType type, Buffer data=Buffer(), unsigned error=EOK);

void handleSockRequest(SockRequestResponse& s);

void setTimeout(Mapping& m, double secondsAhead);

void clearTimeout(Mapping& m);

Packet makeFullPacket(Mapping& m, unsigned char flags, unsigned ack, unsigned seq, Buffer buf);

void sendSyn(MinetHandle& h, Mapping& m);

void printPacket(Packet& p);

void popRetransmitQueue(Mapping& m, unsigned int ack_num);

void startTimer(Mapping& m);


int extractPayload(Mapping& m, Packet& p) {
   Buffer& buf = p.GetPayload();

   //char data[2000];
   unsigned start = 0;
   for(unsigned i = 0; i < buf.GetSize() && buf[i] == 0; ++i)
      start = i+1;
   
   unsigned length = buf.GetSize() - start;
   for(unsigned i = start+length; i > start && buf[i-1] == 0; --i)
      length--;
   
   Buffer & data = buf.Extract(start, length); /////   [!] this is destructive, don't do this
   m.state.RecvBuffer.AddFront(data);
   
   
   cout << "Extracting " << length << " characters: " << data << endl;
   //[!] send buffer upstairs ... somehow
   if (length > 0)
      sendUp(m.connection, WRITE, data); 
   
   m.state.SetLastRecvd(m.state.GetLastRecvd() + length); //there is an alt function that returns a bool if it successfully added the datat to the buffer
   
   return length;
}



int main(int argc, char *argv[])
{
  srand( time(NULL) );

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;
  Time loop_timeout;
  Time now;
  unsigned char stop;
  unsigned int breakpt=0;

/*
  Connection passive_open;
  passive_open.src = MyIPAddr;
  passive_open.dest = IP_ADDRESS_ANY;
  passive_open.srcport = 5050;
  passive_open.destport = PORT_ANY;
  passive_open.protocol = IP_PROTO_TCP;

  //hard code active OPEN connection
  IPAddress foreign_host("129.105.7.216");
  Connection active_open;
  active_open.src = MyIPAddr;
  active_open.dest = foreign_host;
  active_open.srcport = 5050;
  active_open.destport = 1235;
  active_open.protocol = IP_PROTO_TCP;

  TCPState passive_open_state(rand(), LISTEN, NUM_SYN_TRIES);
  TCPState active_open_state(rand(), CLOSED, NUM_SYN_TRIES);

  Mapping passive_open_mapping = Mapping(passive_open, Time(-1), passive_open_state, false);
  Mapping active_open_mapping = Mapping(active_open, Time(-1), active_open_state, false);

  clist.push_back(passive_open_mapping);
  clist.push_back(active_open_mapping);
  */

  //CList::iterator tempcs = clist.FindExactMatching(active_open);
  CList::iterator earliest;

  
/*
  sendSyn(mux, (*tempcs));
  */

  loop_timeout = -1;
  while (MinetGetNextEvent(event, loop_timeout)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
      if(event.eventtype == MinetEvent::Timeout){
        cerr << "Timeout!" << endl;
        earliest = clist.FindEarliest();
        if(earliest != clist.end()){
          for(deque<Packet>::iterator i = earliest->retransmit_queue.begin(); i != earliest->retransmit_queue.end(); ++i){
            Packet& ret = *i;
            TCPHeader th = ret.FindHeader(Headers::TCPHeader);
            if(earliest->state.GetLastRecvd() != 0){
              th.SetAckNum(earliest->state.GetLastRecvd()+1, ret);
              ret.SetHeader(th);
            }
            cerr << "Retransmitting: " << endl;
            printPacket(ret);
            MinetSend(mux, ret);
          }
          earliest->timeout_interval *= 2;
          setTimeout(*earliest, earliest->timeout_interval);
        }
      } else {
        MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
      }
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        
      	Packet p;
      	MinetReceive(mux,p);
      	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "=============RECEIVED PACKET ================" << endl;
      	cerr << "estimated header len="<<tcphlen<<"\n";
      	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
      	printPacket(p);
        cerr << "=============END RECEIVED PACKET ===============" << endl;
        
        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        Connection c;
        ipl.GetSourceIP(c.dest);
        ipl.GetDestIP(c.src);
        ipl.GetProtocol(c.protocol);
        tcph.GetSourcePort(c.destport);
        tcph.GetDestPort(c.srcport);

        CList::iterator cs = clist.FindExactMatching(c);
        if(cs == clist.end()){
          cs = clist.FindMatching(c);
        }
        if(cs != clist.end()){
          cerr << "Matched connection: " << *cs << endl;
          switch (cs->state.GetState())
          {
            case LISTEN:
            {
              cerr << "Connection in LISTEN state" << endl;
              cs->connection.dest = c.dest;
              cs->connection.destport = c.destport;

              unsigned char flags;
              tcph.GetFlags(flags);
              if(IS_SYN(flags)){
                Packet newp;
                unsigned char new_flags = 0;
                unsigned int p_seq_num;
                tcph.GetSeqNum(p_seq_num);
                cs->state.SetLastRecvd(p_seq_num);
                SET_SYN(new_flags);
                SET_ACK(new_flags);
                newp = makeFullPacket(*cs, new_flags, cs->state.GetLastRecvd()+1, cs->state.GetLastSent(), Buffer());
                cerr << "Sending response to SYN" << endl;
                cs->state.SetLastSent(cs->state.GetLastSent()+1);
                printPacket(newp);
                cs->retransmit_queue.push_back(newp);
                startTimer(*cs);
                cs->state.SetState(SYN_RCVD);
                cerr << "State info: " << (*cs) << endl;
                MinetSend(mux, newp);
              } else {
                cerr << "Non-SYN packet received during LISTEN state" << endl;
              }

            }
            break;
            case SYN_RCVD:
            {
              cerr << "Connection SYN_RCVD state" << endl;
              unsigned char flags;
              tcph.GetFlags(flags);
              unsigned int p_seq_num;
              tcph.GetSeqNum(p_seq_num);
              if(p_seq_num == cs->state.GetLastRecvd()+1){
                if(IS_ACK(flags)){
                  unsigned int p_ack_num;
                  tcph.GetAckNum(p_ack_num);
                  if(p_ack_num == cs->state.GetLastSent()){
                    clearTimeout(*cs);
                    cs->state.SetLastRecvd(p_seq_num);
                    cs->state.SetLastAcked(p_ack_num-1);
                    cs->state.SetState(ESTABLISHED);
                    sendUp(cs->connection, WRITE);
                    //maybe process data here
                  } else {
                    cerr << "Unacceptable ACK num" << endl;
                  }
                } else {
                  cerr << "Non-ACK received in SYN_RCVD state, RST" << endl;
                }
              } else {
                cerr << "Invalid packet sequence number" << endl;
              }
            }
            break;
            case SYN_SENT:
            {
              cerr << "Connection in SYN_SENT state" << endl;

              unsigned char flags;
              tcph.GetFlags(flags);
              unsigned int p_ack_num;
              unsigned int p_seq_num;
              if(IS_ACK(flags)){
                tcph.GetAckNum(p_ack_num);
                if(p_ack_num == cs->state.GetLastSent()){
                  clearTimeout(*cs);
                  popRetransmitQueue(*cs, p_ack_num);
                  if(IS_SYN(flags)){
                    tcph.GetSeqNum(p_seq_num);
                    Packet newp;
                    unsigned char new_flags = 0;
                    SET_ACK(new_flags);
                    cs->state.SetLastAcked(p_ack_num-1);
                    cs->state.SetLastRecvd(p_seq_num);
                    cs->state.SetState(ESTABLISHED);
                    Buffer data;
                    //get data from send_buffer
                    newp = makeFullPacket(*cs, new_flags, cs->state.GetLastRecvd()+1, cs->state.GetLastSent(), data);
                    cs->state.SetLastSent(cs->state.GetLastSent()+data.GetSize());
                    printPacket(newp);
                    //cs->retransmit_queue.push_back(newp);
                    MinetSend(mux, newp);
                    sendUp(cs->connection, WRITE);
                    if(data.GetSize()>0){
                      startTimer(*cs);
                    }
                    cerr << "State info: " << (*cs) << endl;
                  } else {
                    cerr << "Expected SYN-ACK" << endl;
                  }
                } else {
                  cerr << "Invalid ACK num" << endl;
                }
              } else {
                cerr << "Received non-ACK packet" << endl;
              }
            }
            break;
            case SYN_SENT1:
            break;
            case ESTABLISHED:
            {
              cerr << "Connection in ESTABLISHED state" << endl;
              bool data_ok = (*cs).state.SetLastRecvd(seqnum,data_len); //check and set last_received
              unsigned char flags;
              tcph.GetFlags(flags);
              unsigned int p_ack_num;
              unsigned int p_seq_num;

              if (IS_ACK(flags)) {
                cs->state.SetLastAcked(p_ack_num); //accumulative ack, so anything before acknum should be acked already
              }
              if (IS_FIN(flags)) {
                cs->state.SetLastRecvd(p_ack_num); //no more data
                cs->state.SetState(CLOSE_WAIT); //change state into CLOSE_WAIT
              } 
              
              unsigned char new_flags = 0;
              SET_ACK(new_flags);
              
              Packet newp;
              // HERE
              // ======
              // newp = makeFullPacket(*cs, new_flags, cs->state.GetLastRecvd()+1, cs->state.GetLastSent(), data);
              // MinetSend(mux, newp);

              SockRequestResponse repl;
              //send packet to socket
              repl.type = WRITE;
              repl.connection = c;
              repl.error = EOK;
              // repl.bytes = data_len;
              // repl.data = data;
              // MinetSend(sock,repl);
            }
            break;
            case SEND_DATA:
            break;
            case CLOSE_WAIT:
            break;
            case FIN_WAIT1:
            break;
            case CLOSING:
            break;
            case LAST_ACK:
            break;
            case FIN_WAIT2:
            break;
            case TIME_WAIT:
            break;
            default:
            break;
          }
        } else {
          cerr << "Unknown connection" << endl;
        }
	       
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
      	SockRequestResponse s;
      	MinetReceive(sock,s);
      	cerr << "Received Socket Request:" << s << endl;
        handleSockRequest(s);
      }
    }
    now.SetToCurrentTime();
    earliest = clist.FindEarliest();
    if(earliest != clist.end()){
      loop_timeout = (double)earliest->timeout - (double)now;
      if((double)loop_timeout > MSL_TIME_SECS)
        loop_timeout = MSL_TIME_SECS;
    } else {
      loop_timeout = -1;
    }
    cerr << "Timeout set to: " << loop_timeout << endl;

  }
  return 0;
}


int sendUp(Connection& c, srrType type, Buffer data, unsigned error) {
   
   SockRequestResponse srr(type,
            c,
            data,
            data.GetSize(),
            error);
  cout << "sending upstairs\n" << srr << endl;
   return MinetSend(sock, srr);
}

/** 
 *  TCP-Socket Layer interface
 */
void handleSockRequest(SockRequestResponse& s) {
  cerr << s << endl;
  switch(s.type) {
    case CONNECT:
    {
       cerr << "Received CONNECT: active open\n";
       clist.push_front(Mapping(s.connection,Time(0.0),TCPState(rand(), SYN_SENT, 0),false));
       Mapping& m = *clist.FindExactMatching(s.connection);
       sendUp(m.connection, STATUS);
       sendSyn(mux, m);
       break;
    }
    case ACCEPT:
    {
       cerr << "Received ACCEPT: new connection\n";
       clist.push_front(Mapping(s.connection,Time(2.0),TCPState(rand(), LISTEN, 0),false));
       CList::iterator i = clist.FindExactMatching(s.connection);
       Mapping& m = *i;
       m.connection = s.connection;
       sendUp(m.connection, STATUS);
       break;
    }     
    case WRITE:
    {
       Mapping& m = *clist.FindMatching(s.connection);
       m.state.SendBuffer.AddBack(s.data);
       sendUp(m.connection, STATUS);
       setTimeout(m, 0);
       break;
    }
    case FORWARD:
    {
       Mapping& m = *clist.FindMatching(s.connection);
       sendUp(m.connection, STATUS);
       break;
    }
    case CLOSE:
    {
       cerr << "Received CLOSE" << endl;
       CList::iterator i = clist.FindMatching(s.connection);
       if (i == clist.end()) {
          cerr << " CLOSING \n";
          unsigned char flags = 0;
          SET_FIN(flags);  SET_ACK(flags);
          Mapping& m = *i;
          m.state.SetLastRecvd(m.state.GetLastRecvd() + 1);
          Packet last = makeFullPacket(m, flags, m.state.GetLastRecvd(), m.state.GetLastSent(), Buffer());
          cerr << last << endl;
          MinetSend(mux, last);
          m.state.SetState(LAST_ACK);
       } else {
          clist.erase(i);
       }
       break;
    }   
    case STATUS:
    {
       cerr << "Received STATUS" << endl;
       // CList::iterator i = clist.FindMatching(s.connection);
       // Mapping& m = *i;
       // m.connection = s.connection;
       //sendUp(m.connection, STATUS);
     break;
     }
  }
}

void setTimeout(Mapping& m, double secondsAhead) {
  
  m.timeout.SetToCurrentTime();
  /*
  m.timeout.tv_sec += (long)(secondsAhead);
  const long aMilli = (long) pow(10,6);
  m.timeout.tv_usec += ((long)(secondsAhead*aMilli)%aMilli);
  */
  m.timeout = (double)m.timeout + secondsAhead;
  m.bTmrActive = true;
}

void clearTimeout(Mapping& m)
{
  m.bTmrActive = false;

}

void startTimer(Mapping& m)
{
  m.computeTimeout();
  setTimeout(m, m.timeout_interval);
}

Packet makeFullPacket(Mapping& m, unsigned char flags, unsigned ack, unsigned seq, Buffer buf) {
  Packet out(buf);
  Connection & connection = m.connection;
  unsigned windowSize = m.state.GetRwnd();
   
  // Build IP header
  IPHeader ih;
  ih.SetProtocol(IP_PROTO_TCP);
  ih.SetSourceIP(connection.src);
  ih.SetDestIP(connection.dest);
  ih.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + buf.GetSize());

  out.PushFrontHeader(ih);
  
  // Build TCP header
  TCPHeader th;
  th.SetSourcePort(connection.srcport, out);
  th.SetDestPort(connection.destport, out);
  th.SetSeqNum(seq, out);
  th.SetAckNum(ack, out);
  th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, out);
  th.SetWinSize(windowSize, out);
  th.SetFlags(flags, out);
   
  // Set tcp header BEHIND the IP header
  out.PushBackHeader(th);

  return out;
}

void printPacket(Packet& p) {
  IPHeader ipl=p.FindHeader(Headers::IPHeader);
  TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

  unsigned short packet_len;
  unsigned char ip_header_len;
  unsigned char tcphlen;
  ipl.GetTotalLength(packet_len);
  ipl.GetHeaderLength(ip_header_len);
  tcph.GetHeaderLen(tcphlen);
  ip_header_len *= 4;
  tcphlen *= 4;
  size_t data_len = packet_len - (unsigned)ip_header_len - (unsigned)tcphlen;

  cerr << " =============== PACKET =============== " << endl;
  cerr << "IP Header = " << ipl << " and " << endl;
  cerr << "TCP Header = " << tcph << " and " << endl;
  cerr << "Checksum = " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID")<< endl;
  cerr << "Packet length = " << packet_len << endl;
  cerr << "IP Header length = " << (unsigned)ip_header_len << endl;
  Buffer& data = p.GetPayload();
  cerr << "App Data length = " << data_len << endl;
  cerr << "App Data = " << data.ExtractFront(data_len) << endl;
  cerr << " ============== / PACKET ============== " << endl;
}

void sendSyn(MinetHandle& h, Mapping& m)
{
  Packet syn;
  unsigned char new_flags = 0;
  SET_SYN(new_flags);
  syn = makeFullPacket(m, new_flags, 0, m.state.GetLastSent(), Buffer());
  cerr << "Sending SYN" << endl;
  printPacket(syn);
  //sendRTTProbe(m);
  m.state.SetLastSent(m.state.GetLastSent()+1);
  startTimer(m);
  m.retransmit_queue.push_back(syn);
  MinetSend(h, syn);
  m.state.SetState(SYN_SENT);
  cerr << "State info: " << m << endl;
}

void popRetransmitQueue(Mapping& m, unsigned int ack_num)
{
  deque<Packet>::iterator i = m.retransmit_queue.begin();
  TCPHeader th;
  unsigned int seq_num;

  while(i != m.retransmit_queue.end()){
    th = i->FindHeader(Headers::TCPHeader);
    th.GetSeqNum(seq_num);
    if(seq_num < ack_num){
      m.retransmit_queue.pop_front();
      i = m.retransmit_queue.begin();
    } else {
      break;
    }
  }
}
