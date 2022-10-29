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
from ryu.lib.packet import ethernet, tcp, udp, ipv4
from ryu.lib.packet import ether_types


class SimpleSW(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSW, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ethtype = eth.ethertype

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        ippkt = pkt.__contains__(ipv4.ipv4) # if packet contains IP
        tcppkt = pkt.__contains__(tcp.tcp) # if packet contains tcppkt
        udppkt = pkt.__contains__(udp.udp) # if packet contains udppkt
        

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        
        
        # ------------------------
        # match
        # basic match
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            print('LLDP protocol ...')
            # process LLDP packet
            return

        elif ippkt: # extended matches
            print("ip")
            ipp = pkt.get_protocols(ipv4.ipv4)[0]
            if tcppkt:
                print("in tcp")
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
        else:
            print('else unknoen packet')
            match = parser.OFPMatch(eth_dst=dst_mac,eth_src=src_mac,eth_type=eth.ethertype)
        #actions

        # -------------------------
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)