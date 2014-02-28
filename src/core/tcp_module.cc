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

typedef ConnectionList<TCPState> CList;
typedef ConnectionToStateMapping<TCPState> Mapping;
CList clist;
MinetHandle mux;
MinetHandle sock;


unsigned int generateISN();

void printPacket(Packet& p);

void send_packet (MinetHandle& h, Packet& p);

void send_syn(MinetHandle& h, ConnectionToStateMapping<TCPState>& c, ConnectionToRTTMapping& r);

template<class STATE> 
typename ConnectionList<STATE>::iterator FindExactMatching(const Connection& rhs, ConnectionList<STATE>& clist);

std::deque<ConnectionToRTTMapping>::iterator FindExactMatching(const Connection& rhs, std::deque<ConnectionToRTTMapping>& rttlist);

std::deque<ConnectionToRTTMapping>::iterator FindMatching(const Connection& rhs, std::deque<ConnectionToRTTMapping>& rttlist);

int sendUp(Connection& c, srrType type, Buffer data=Buffer(), unsigned error=EOK) {
  SockRequestResponse s(type,c,data,data.GetSize(),error);
  cout << "sending packet up\n" << s << endl;
  return MinetSend(sock, s);
}

void setTimeout(Mapping& m, double secondsAhead) {
  m.timeout.SetToCurrentTime();
  m.timeout.tv_sec += (long)(secondsAhead);
  const long aMilli = (long) pow(10,6);
  m.timeout.tv_usec += ( (long)(secondsAhead*aMilli)%aMilli);
  m.bTmrActive = true;
}

void clearTimeout(Mapping& m) {
  m.bTmrActive = false;
  m.state.tmrTries = 0;
}
void kill(Mapping& m) {
   sendUp(m.connection, WRITE, Buffer(), ECONN_FAILED);
   m.state.SetState(CLOSED);
   clearTimeout(m);
   //clist.erase(clist.FindMatching(m.connection));
}
/**
 *  Create outgoing packet
 */
Packet makeFullPacket(Mapping& m, unsigned char flags, unsigned ack, unsigned seq, Buffer buf) {
  
  Packet out(buf);
   
  Connection & connection = m.connection;
  unsigned windowSize = m.state.GetN();
   
  // Build IP header
  IPHeader ih;
   
  ih.SetProtocol(IP_PROTO_TCP);
  ih.SetSourceIP(connection.src);
  ih.SetDestIP(connection.dest);
  ih.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + buf.GetSize());
            
  out.PushFrontHeader(ih);
  
  // Build TCP header
  TCPHeader th;
  th.SetFlags(flags, out);
   
  th.SetSourcePort(connection.srcport, out);
  th.SetDestPort(connection.destport, out);
  th.SetAckNum(ack, out);
  th.SetSeqNum(seq, out);
  th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, out);

  th.SetWinSize(windowSize, out);

  if(IS_SYN(flags)) {
    TCPOptions op;
    op.data[0] = TCP_HEADER_OPTION_KIND_MSS;
    op.data[1] = TCP_HEADER_OPTION_KIND_MSS_LEN;
    op.data[2] = 0;
    op.data[3] = 256;
    op.data[4] = 1;
    op.data[5] = 1;
    op.data[5] = 1;
    op.data[7] = 0;
    op.len = 8;
    th.SetOptions(op);
  }
   
   // Set tcp header BEHIND the IP header
   out.PushBackHeader(th);
   return out;
}

Packet makePacket(Mapping& m, unsigned char flags, Buffer buf=Buffer()) {
  unsigned ack = m.state.GetLastRecvd();
  unsigned seq = m.state.GetLastSent();
  return makeFullPacket(m, flags, ack, seq, buf);
}

/** 
 *  TCP-Socket Layer interface
 */
void handleSockRequest(SockRequestResponse& s) {
  cout << s << endl;
  
  switch(s.type) {
      case CONNECT:
      {
         cout << "Received CONNECT: active open\n";
         clist.push_front(Mapping(s.connection,Time(0.0),TCPState(rand(), SYN_SENT, 0),true));
         Mapping& m = *clist.FindMatching(s.connection);
         sendUp(m.connection, STATUS);
         break;
      }
      case ACCEPT:
      {
         cout << "Received ACCEPT: new connection\n";
         clist.push_front(Mapping(s.connection,Time(2.0),TCPState(rand(), LISTEN, 0),false));
         CList::iterator i = clist.FindMatching(s.connection);
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
         cout << "Received CLOSE" << endl;
         CList::iterator i = clist.FindMatching(s.connection);
         if (i == clist.end()) {
            sendUp(s.connection, STATUS, Buffer(), ECONN_FAILED);   
         } else {
            clist.erase(i);
         }
         break;
      }   
      case STATUS:
         cout << "Received STATUS" << endl;
         CList::iterator i = clist.FindMatching(s.connection);
         Mapping& m = *i;
         m.connection = s.connection;
         //sendUp(m.connection, STATUS);
         
         if(s.error == 12) {        // closing 
            cout << " CLOSING \n";
            unsigned char flags = 0;
            SET_FIN(flags);  SET_ACK(flags);
            m.state.SetLastRecvd(m.state.GetLastRecvd() + 1);
            Packet last = makePacket(m, flags);
            cout << last << endl;
            MinetSend(mux, last);
            m.state.SetState(LAST_ACK);
         }
         break;
   }
}

int main(int argc, char *argv[])
{

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

  cerr << "Setting up connection list" << endl;
  // ConnectionList<TCPState> clist;
  std::deque<ConnectionToRTTMapping> rttlist;

  //hard code passive OPEN connection
  Connection passive_open;
  passive_open.src = MyIPAddr;
  passive_open.dest = IP_ADDRESS_ANY;
  passive_open.srcport = 5050;
  passive_open.destport = PORT_ANY;
  passive_open.protocol = IP_PROTO_TCP;

  //hard code active OPEN connection
  IPAddress foreign_host("129.105.7.234");
  Connection active_open;
  active_open.src = MyIPAddr;
  active_open.dest = foreign_host;
  active_open.srcport = 5050;
  active_open.destport = 1230;
  active_open.protocol = IP_PROTO_TCP;

  ConnectionToRTTMapping passive_open_rtt(passive_open);
  ConnectionToRTTMapping active_open_rtt(active_open);

  cerr << "Hard-coded passive open connection: " << passive_open << endl;
  cerr << "Hard-coded active open connection: " << active_open << endl;

  TCPState passive_open_state(generateISN(), LISTEN, NUM_SYN_TRIES);
  TCPState active_open_state(generateISN(), CLOSED, NUM_SYN_TRIES);

  ConnectionToStateMapping<TCPState> passive_open_mapping = ConnectionToStateMapping<TCPState>(passive_open, Time(-1), passive_open_state, false);
  ConnectionToStateMapping<TCPState> active_open_mapping = ConnectionToStateMapping<TCPState>(active_open, Time(-1), active_open_state, false);

  clist.push_back(passive_open_mapping);
  rttlist.push_back(passive_open_rtt);
  clist.push_back(active_open_mapping);
  rttlist.push_back(active_open_rtt);

  ConnectionList<TCPState>::iterator tempcs = FindExactMatching(active_open, clist);
  std::deque<ConnectionToRTTMapping>::iterator temprs = FindExactMatching(active_open, rttlist);

  send_syn(mux, (*tempcs), (*temprs));
  send_syn(mux, (*tempcs), (*temprs));
  send_syn(mux, (*tempcs), (*temprs));

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);

        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "\nestimated header len=" << tcphlen << endl;
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);


        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
        unsigned short packet_len;
        unsigned char ip_header_len;
        ipl.GetTotalLength(packet_len);
        ipl.GetHeaderLength(ip_header_len);
        ip_header_len *= 4;
        size_t data_len = packet_len - (unsigned)ip_header_len - tcphlen;
        unsigned int seq_num;

        printPacket(p);

        Connection c;
        ipl.GetSourceIP(c.dest);
        ipl.GetDestIP(c.src);
        ipl.GetProtocol(c.protocol);
        tcph.GetSourcePort(c.destport);
        tcph.GetDestPort(c.srcport);

        ConnectionList<TCPState>::iterator cs = FindExactMatching(c, clist);
        std::deque<ConnectionToRTTMapping>::iterator rs;
        if(cs == clist.end()){
          cs = clist.FindMatching(c);
          rs = FindMatching(c, rttlist);
        } else {
          rs = FindExactMatching(c, rttlist);
        }
        if(cs!=clist.end()){
          cerr << "Matched connection:\n" << (*cs) << endl;
          cerr << "RTT mapping:\n" << (*rs) << endl;
          switch(cs->state.GetState()){
            case LISTEN:
            {
              cerr << "Connection in LISTEN state" << endl;
              cs->connection.dest = c.dest;
              cs->connection.destport = c.destport;
              rs->connection.dest = c.dest;
              rs->connection.destport = c.destport;
              unsigned char flags;
              tcph.GetFlags(flags);
              cerr << "Flags: " << (unsigned)flags << endl;
              if(IS_SYN(flags)){
                Packet syn_ack;
                IPHeader ih;
                TCPHeader th;
                unsigned int p_seq_num;
                unsigned char new_flags = 0;
                tcph.GetSeqNum(p_seq_num);
                cs->state.SetLastRecvd(p_seq_num);

                ih.SetProtocol(IP_PROTO_TCP);
                ih.SetSourceIP(cs->connection.src);
                ih.SetDestIP(cs->connection.dest);
                ih.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
                syn_ack.PushFrontHeader(ih);

                cerr << "IP Header: " << ih << endl;

                th.SetSourcePort(cs->connection.srcport, syn_ack);
                th.SetDestPort(cs->connection.destport, syn_ack);
                th.SetSeqNum(cs->state.GetLastSent(), syn_ack);
                th.SetAckNum(cs->state.GetLastRecvd()+1, syn_ack);
                th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, syn_ack);
                th.SetWinSize(cs->state.TCP_BUFFER_SIZE, syn_ack);
                SET_SYN(new_flags);
                SET_ACK(new_flags);
                th.SetFlags(new_flags, syn_ack);
                syn_ack.PushBackHeader(th);

                cerr << "TCP Header: " << th << endl;
                cerr << "Sending response to SYN" << endl;
                printPacket(syn_ack);
                rs->seq_num = cs->state.GetLastSent();
                rs->time_sent.SetToCurrentTime();
                cs->timeout = 1;
                cs->bTmrActive = true;
                send_packet(mux, syn_ack);

                cs->state.SetState(SYN_RCVD);
                cerr << "State info: " << (*cs) << endl;
                cerr << "RTT Measure info: " << (*rs) << endl;
              } else {
                cerr << "Non-SYN packet received by LISTEN connection" << endl;
              }
            }
            break;
            case SYN_RCVD:
            break;
            case SYN_SENT:
            {
              cerr << "Connection in SYN_SENT state" << endl;

              unsigned char flags;
              tcph.GetFlags(flags);
              cerr << "Flags: " << (unsigned)flags << endl;
              unsigned int ack_num;
              if(IS_ACK(flags)){
                tcph.GetAckNum(ack_num);
                if(ack_num-1 >= cs->state.GetLastAcked() && ack_num-1 <= cs->state.GetLastSent()){ //ack_num is OK
                  if(IS_SYN(flags)){
                    unsigned int p_seq_num;
                    tcph.GetSeqNum(p_seq_num);
                    cs->state.SetLastRecvd(p_seq_num);
                    cs->state.SetLastAcked(ack_num);
                    Packet ackp;
                    IPHeader ih;
                    TCPHeader th;
                    unsigned char new_flags = 0;

                    ih.SetProtocol(IP_PROTO_TCP);
                    ih.SetSourceIP(cs->connection.src);
                    ih.SetDestIP(cs->connection.dest);
                    ih.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH); //change this line, could have data to send
                    ackp.PushFrontHeader(ih);

                    cerr << "IP Header: " << ih << endl;

                    th.SetSourcePort(cs->connection.srcport, ackp);
                    th.SetDestPort(cs->connection.destport, ackp);
                    th.SetSeqNum(cs->state.GetLastSent()+1, ackp);
                    th.SetAckNum(cs->state.GetLastRecvd()+1, ackp);
                    th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, ackp);
                    th.SetWinSize(cs->state.TCP_BUFFER_SIZE, ackp);
                    SET_ACK(new_flags);
                    th.SetFlags(new_flags, ackp);
                    ackp.PushBackHeader(th);

                    cs->state.SetLastSent(cs->state.GetLastSent()+1);

                    cerr << "TCP Header: " << th << endl;
                    cerr << "Sending ACK to SYN" << endl;
                    printPacket(ackp);
                    rs->seq_num = cs->state.GetLastSent();
                    rs->time_sent.SetToCurrentTime();
                    cs->timeout = 1;
                    cs->bTmrActive = true;
                    send_packet(mux, ackp);

                    cs->state.SetState(ESTABLISHED);
                    cerr << "State info: " << (*cs) << endl;
                    cerr << "RTT Measure info: " << (*rs) << endl;
                  }
                } else {
                  cerr << "Received an ACK out of bounds" << endl;
                }
              } else {
                cerr << "Received non-ACK packet" << endl;
              }
            }
            break;
            case SYN_SENT1:
            break;
            case ESTABLISHED:
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
          cerr << "Unknown port/5-tuple" << endl;
        }
      }
      //  Data from the Sockets layer above  //
      if (event.handle == sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;
        // HANDLE SOCK REQUEST
        // handleSockRequest(s);
      }
    }
  }
  cerr << "Reached end of main" << endl;
  return 0;
}

unsigned int generateISN()
{
  return 5000;
}

void printPacket(Packet& p)
{
  
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

  cerr << "TCP Packet: IP Header is "<<ipl<<" and "<<endl;
  cerr << "TCP Header is "<<tcph << " and "<<endl;

  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID")<<endl;

  cerr << "Packet length: " << packet_len << endl;
  cerr << "IP Header length: " << (unsigned)ip_header_len << endl;
  cerr << "App data length: " << data_len << endl;
  Buffer& data = p.GetPayload();
  cerr << "Application data size: " << data_len << endl;
  cerr << "Application data: " << data.ExtractFront(data_len) << endl;

  
}

void send_packet (MinetHandle& h, Packet& p)
{
  MinetSend(h, p);
}


template<class STATE>
typename ConnectionList<STATE>::iterator FindExactMatching(const Connection& rhs, ConnectionList<STATE>& clist)
{
  Connection c;
  for(typename ConnectionList<STATE>::iterator i = clist.begin(); i != clist.end(); ++i){
    c = (*i).connection;
    if(c.src == rhs.src && c.dest == rhs.dest && c.srcport == rhs.srcport && c.destport == rhs.destport && c.protocol == rhs.protocol){
      return i;
    }
  }
  return clist.end();
}

std::deque<ConnectionToRTTMapping>::iterator FindExactMatching(const Connection& rhs, std::deque<ConnectionToRTTMapping>& rttlist)
{
  Connection c;
  for(std::deque<ConnectionToRTTMapping>::iterator i = rttlist.begin(); i != rttlist.end(); ++i){
    c = (*i).connection;
    if(c.src == rhs.src && c.dest == rhs.dest && c.srcport == rhs.srcport && c.destport == rhs.destport && c.protocol == rhs.protocol){
      return i;
    }
  }
  return rttlist.end();
}

std::deque<ConnectionToRTTMapping>::iterator FindMatching(const Connection& rhs, std::deque<ConnectionToRTTMapping>& rttlist)
{
  for(std::deque<ConnectionToRTTMapping>::iterator i = rttlist.begin(); i != rttlist.end(); ++i){
    if((*i).Matches(rhs)){
      return i;
    }
  }
  return rttlist.end();
}

void send_syn(MinetHandle& h, ConnectionToStateMapping<TCPState>& c, ConnectionToRTTMapping& r)
{
  cerr << "Making SYN packet" << endl;
  Packet syn;
  IPHeader ih;
  TCPHeader th;
  unsigned int p_seq_num;
  unsigned char new_flags = 0;

  ih.SetProtocol(IP_PROTO_TCP);
  ih.SetSourceIP(c.connection.src);
  ih.SetDestIP(c.connection.dest);
  ih.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
  syn.PushFrontHeader(ih);

  cerr << "IP Header: " << ih << endl;

  th.SetSourcePort(c.connection.srcport, syn);
  th.SetDestPort(c.connection.destport, syn);
  th.SetSeqNum(c.state.GetLastSent(), syn);
  th.SetAckNum(0, syn);
  th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, syn);
  th.SetWinSize(c.state.TCP_BUFFER_SIZE, syn);
  SET_SYN(new_flags);
  th.SetFlags(new_flags, syn);
  syn.PushBackHeader(th);

  cerr << "TCP Header: " << th << endl;
  cerr << "Sending SYN" << endl;
  printPacket(syn);
  r.seq_num = c.state.GetLastSent();
  r.time_sent.SetToCurrentTime();
  c.timeout = 1;
  c.bTmrActive = true;
  send_packet(h, syn);
  c.state.stateOfcnx = SYN_SENT;
  cerr << "State info: " << c << endl;
  cerr << "RTT Measure info: " << r << endl;
}