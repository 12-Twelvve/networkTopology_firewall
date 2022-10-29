# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,tcp,ipv4,udp,icmp
from ryu.lib.packet import ether_types
from ryu.ofproto.inet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,IPPROTO_SCTP
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP,ETH_TYPE_LLDP,ETH_TYPE_MPLS,ETH_TYPE_IPV6

ICMP_PING = 8
ICMP_PONG = 0
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_BOGUS_FLAGS = 0x15

rules ={
    '192.168.1.50': 
        (('192.168.1.51', 'ICMP', '-', '-', 'PING', 'ALLOW'),
        ('192.168.1.10', 'ICMP', '-', '-', 'PONG', 'ALLOW'), 
        ('192.168.1.11', 'ICMP', '-', '-', 'PONG', 'ALLOW'), 
        ('192.168.1.12', 'ICMP', '-', '-', 'PONG', 'ALLOW'), 
        ('192.168.1.13', 'ICMP', '-', '-', 'PONG', 'ALLOW'), 
        ('192.168.1.51', 'TCP', 'ANY', 'ANY', 'ANY', 'ALLOW'), 
        ('192.168.1.10', 'TCP', 'ANY', 'ANY', 'ACK', 'ALLOW'), 
        ('192.168.1.11', 'TCP', 'ANY', 'ANY', 'ACK', 'ALLOW'), 
        ('192.168.1.12', 'TCP', 'ANY', 'ANY', 'ACK', 'ALLOW'), 
        ('192.168.1.13', 'TCP', 'ANY', 'ANY', 'ACK', 'ALLOW'), 
        ('192.168.1.254', 'TCP', '80', '80', 'ACK', 'ALLOW'), 
        ('192.168.1.51', 'UDP', '-', '-', '-', 'ALLOW'), 
        ('192.168.1.10', 'UDP', '-', '-', '-', 'ALLOW'), 
        ('192.168.1.11', 'UDP', '-', '-', '-', 'ALLOW'), 
        ('192.168.1.12', 'UDP', '-', '-', '-', 'ALLOW'), 
        ('192.168.1.13', 'UDP', '-', '-', '-', 'ALLOW')),
    '192.168.1.10': 
        (('192.168.1.50', 'ICMP', '-', '-', 'PING', 'ALLOW'), 
        ('192.168.1.50', 'TCP', 'ANY', 'ANY', 'ANY', 'ALLOW'), 
        ('192.168.1.50', 'UDP', '-', '-', '-', 'ALLOW')), 
    '192.168.1.11': 
        (('192.168.1.50', 'ICMP', '-', '-', 'PING', 'ALLOW'), 
        ('192.168.1.50', 'TCP', 'ANY', 'ANY', 'ANY', 'ALLOW'), 
        ('192.168.1.50', 'UDP', '-', '-', '-', 'ALLOW')), 
    '192.168.1.12': 
        (('192.168.1.50', 'ICMP', '-', '-', 'PING', 'ALLOW'), 
        ('192.168.1.50', 'TCP', 'ANY', 'ANY', 'ANY', 'ALLOW'), 
        ('192.168.1.50', 'UDP', '-', '-', '-', 'ALLOW')), 
    '192.168.1.13': 
        (('192.168.1.50', 'ICMP', '-', '-', 'PING', 'ALLOW'), 
        ('192.168.1.50', 'TCP', 'ANY', 'ANY', 'ANY', 'ALLOW'), 
        ('192.168.1.50', 'UDP', '-', '-', '-', 'ALLOW')), 
    '192.168.1.51': 
        (('192.168.1.50', 'ICMP', '-', '-', 'PONG', 'ALLOW'), 
        ('192.168.1.50', 'TCP', 'ANY', 'ANY', 'ACK', 'ALLOW'), 
        ('192.168.1.50', 'UDP', '-', '-', '-', 'ALLOW')), 
    '192.168.1.254': 
        (('192.168.1.50', 'TCP', '80', '80', 'ANY', 'ALLOW'),)
    
    }


class SimpleSwitch12(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch12, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.inner_policy = rules

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
       
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ethtype = eth.ethertype

        ippkt = pkt.__contains__(ipv4.ipv4) # if packet contains IP
        tcppkt = pkt.__contains__(tcp.tcp) # if packet contains tcppkt
        udppkt = pkt.__contains__(udp.udp) # if packet contains udppkt
        
        dst_mac = eth.dst
        src_mac = eth.src

        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        dst = eth.dst
        src = eth.src
        self.mac_to_port[dpid][src] = in_port

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
 
        action_drop = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        actions_default =  [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        if ippkt: # extended matches
            # print("ip")
            # check rules for different ips and sets flags for dropping or forwarding
            flag = False  # access flag
            ipp = pkt.get_protocols(ipv4.ipv4)[0]
            if tcppkt:
                # print('tcp')
                tcpp = pkt.get_protocols(tcp.tcp)[0]
                # tcpo = pkt.get_protocols(tcp.tcp)
                # print(tcpo,'----',tcpp)
            if udppkt:
                udpp = pkt.get_protocols(udp.udp)[0]
            if ((ipp.proto == IPPROTO_ICMP)):
                # print('icmp')
                icmpob = pkt.get_protocol(icmp.icmp)
            if (ipp.src in self.inner_policy):
                temp = self.inner_policy.get(ipp.src)
                for i in range(len(temp)):
                    # TCP 
                    if (tcppkt and (temp[i][0] == ipp.dst) and (temp[i][1]=='TCP') and  (temp[i][5] == 'ALLOW')):
                        if ((temp[i][2] == 'ANY') and (temp[i][3] == 'ANY') and (temp[i][4] == 'ANY')):
                            flag = True # all port
                            break
                        elif ((temp[i][2] == 'ANY') and (temp[i][3] == 'ANY') and (temp[i][4]== 'ACK') and ((tcpp.bits & TCP_ACK) == TCP_ACK)):
                            flag=True #ack -all port
                            break
                        elif ((int(temp[i][3])==tcpp.dst_port) and (temp[i][4] == 'ANY') ):
                            flag = True #80 port for http
                            break
                        elif ((int(temp[i][2])==tcpp.src_port) and (temp[i][4]== 'ACK') and ((tcpp.bits & TCP_ACK) == TCP_ACK)):
                            flag=True #ack - 80 port for http
                            break
                    # UDP
                    elif (udppkt and (temp[i][0]==ipp.dst) and (temp[i][1]=='UDP') and (temp[i][5]=='ALLOW')):
                        flag = True
                        break
                    # ICMP
                    elif ((temp[i][0]==ipp.dst)and (ipp.proto == IPPROTO_ICMP) and (temp[i][1]=='ICMP') and (temp[i][5]=='ALLOW')):
                        if ((temp[i][4]=='PING') or ((temp[i][4]=='PONG') and (icmpob.type == ICMP_PONG)) ):
                            print('ping or pong')
                            flag = True
                            break
                    
            if not(flag):
                actions_default = action_drop

            if (ipp.proto  == IPPROTO_ICMP):
                
                match = parser.OFPMatch(in_port = in_port, eth_type = ether_types.ETH_TYPE_IP, ip_proto= ipp.proto , 
                                        ipv4_src = ipp.src, ipv4_dst = ipp.dst)
            if tcppkt:
                tcpp = pkt.get_protocols(tcp.tcp)[0]
                match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=ipp.proto,ipv4_dst=ipp.dst,ipv4_src=ipp.src,
                                        tcp_src=tcpp.src_port,tcp_dst=tcpp.dst_port)
                
            elif udppkt:
                udpp = pkt.get_protocols(udp.udp)[0]
                match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=ipp.proto,ipv4_dst=ipp.dst,ipv4_src=ipp.src,
                                        udp_src=udpp.src_port,udp_dst=udpp.dst_port)
            else:
                match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=ipp.proto,ipv4_dst=ipp.dst,ipv4_src=ipp.src)
        

        elif(ethtype == ETH_TYPE_ARP):
            print('ARP packet') 
            match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=eth.ethertype)
        else: # drop unknown packets.
            match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=eth.ethertype)
            actions_default = action_drop
        
        #actions
        if actions_default == action_drop: 
            out_port = ''
            # print('drop')
            actions = [] # empty action indicates a 'drop' function

        else: # if not blocking port, just allow based on mac address else, flood to discover
            if dst in self.mac_to_port[dpid]:
                # print('mactoport')
                out_port = self.mac_to_port[dpid][dst]
            else:
                # print('flood')
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        # install a flow table to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        else: # incase its flood pkt
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
    