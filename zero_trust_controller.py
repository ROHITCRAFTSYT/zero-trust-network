#!/usr/bin/python

"""
Zero Trust Network Controller using Ryu SDN Framework
This controller implements zero-trust principles by:
1. Verifying all connections through authentication
2. Applying least-privilege access policies
3. Monitoring all traffic continuously
4. Implementing micro-segmentation
5. Denying all connections by default
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.app.wsgi import WSGIApplication
from ryu.lib import hub
import requests
import json
import time

# Zero Trust implementation constants
AUTH_SERVER_IP = '10.0.4.2'
AUTH_SERVER_PORT = 8080
POLICY_SERVER_IP = '10.0.4.3'
POLICY_SERVER_PORT = 8081

# Known MAC addresses (for simulation - in production this would be dynamic)
KNOWN_DEVICES = {
    '00:00:00:00:01:02': {'id': 'trusted-host1', 'zone': 'trusted', 'ip': '10.0.1.2'},
    '00:00:00:00:01:03': {'id': 'trusted-host2', 'zone': 'trusted', 'ip': '10.0.1.3'},
    '00:00:00:00:02:02': {'id': 'dmz-server1', 'zone': 'dmz', 'ip': '10.0.2.2'},
    '00:00:00:00:02:03': {'id': 'dmz-server2', 'zone': 'dmz', 'ip': '10.0.2.3'},
    '00:00:00:00:03:02': {'id': 'untrusted-host', 'zone': 'untrusted', 'ip': '10.0.3.2'},
    '00:00:00:00:04:02': {'id': 'auth-server', 'zone': 'core', 'ip': '10.0.4.2'},
    '00:00:00:00:04:03': {'id': 'policy-server', 'zone': 'core', 'ip': '10.0.4.3'},
}

class ZeroTrustController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(ZeroTrustController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.authenticated_flows = {}
        self.session_tokens = {}
        
        # Start a background thread for periodic verification
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.logger.info("Zero Trust Controller Started")
    
    def _monitor(self):
        """
        Background thread to periodically verify authentication status
        and revoke access if needed (implements continuous verification)
        """
        while True:
            # Check all sessions and verify they're still valid
            current_time = time.time()
            expired_sessions = []
            
            for flow_id, data in self.authenticated_flows.items():
                # In a real implementation, we would call the auth server
                # For simulation, we'll expire sessions after 300 seconds
                if current_time - data['timestamp'] > 300:
                    expired_sessions.append(flow_id)
            
            # Remove expired sessions
            for flow_id in expired_sessions:
                self.logger.info(f"Revoking access for expired session: {flow_id}")
                del self.authenticated_flows[flow_id]
                
                # In a real implementation, we would also remove flow rules
                # from switches for this session
            
            # Sleep for 30 seconds before next check
            hub.sleep(30)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Initial setup of switches - install default deny-all rules
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default table-miss flow entry (drop unknown packets)
        match = parser.OFPMatch()
        actions = []  # No actions means drop
        self.add_flow(datapath, 0, match, actions)
        
        # Allow basic network services like DHCP, DNS
        # In a real zero-trust implementation, these would also be verified
        # For this prototype, we'll allow them for demonstration purposes
        
        # Allow DHCP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ip_proto=17,  # UDP
                               udp_src=67,
                               udp_dst=68)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)
        
        # Allow DNS
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ip_proto=17,  # UDP
                               udp_dst=53)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)
        
        # Allow traffic to auth and policy servers (essential for zero trust)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_dst=AUTH_SERVER_IP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_dst=POLICY_SERVER_IP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """Helper function to add a flow entry to a switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match,
                                   instructions=inst, hard_timeout=hard_timeout,
                                   idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst,
                                   hard_timeout=hard_timeout,
                                   idle_timeout=idle_timeout)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle incoming packets and apply zero-trust policies
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        # Get source and destination MAC addresses
        src_mac = eth.src
        dst_mac = eth.dst
        
        # Device identification from MAC (simulated)
        src_device = KNOWN_DEVICES.get(src_mac, {'id': 'unknown', 'zone': 'untrusted'})
        dst_device = KNOWN_DEVICES.get(dst_mac, {'id': 'unknown', 'zone': 'untrusted'})
        
        # Extract IP information if available
        ip_proto = None
        src_ip = None
        dst_ip = None
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip.src
            dst_ip = ip.dst
            ip_proto = ip.proto
            
            # Create a flow ID to track this connection
            flow_id = f"{src_ip}:{dst_ip}"
            
            # Zero Trust Verification
            if flow_id not in self.authenticated_flows:
                # This connection hasn't been authenticated yet
                
                # In a real implementation, we would query the auth and policy servers
                # For simulation, we'll implement basic rules:
                
                # 1. Traffic to/from auth and policy servers is always allowed
                if dst_ip == AUTH_SERVER_IP or dst_ip == POLICY_SERVER_IP:
                    self.logger.info(f"Allowing traffic to auth/policy server: {flow_id}")
                    # Forward the packet
                    self._handle_authenticated_packet(datapath, msg, in_port, src_mac, dst_mac)
                    return
                
                # 2. Check zone-based policies
                allowed = False
                
                # Trusted zone can access DMZ servers
                if src_device['zone'] == 'trusted' and dst_device['zone'] == 'dmz':
                    allowed = True
                    
                # DMZ servers can only respond to established connections
                elif src_device['zone'] == 'dmz' and dst_device['zone'] == 'trusted':
                    # Check if there's an established connection
                    reverse_flow = f"{dst_ip}:{src_ip}"
                    if reverse_flow in self.authenticated_flows:
                        allowed = True
                
                # Untrusted zone has minimal access
                elif src_device['zone'] == 'untrusted':
                    # Only allow untrusted hosts to access authentication
                    if dst_ip == AUTH_SERVER_IP:
                        allowed = True
                    else:
                        allowed = False
                
                if allowed:
                    # Record this authentication decision
                    self.authenticated_flows[flow_id] = {
                        'src_mac': src_mac,
                        'dst_mac': dst_mac,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'timestamp': time.time()
                    }
                    
                    self.logger.info(f"Zero Trust: Authenticated flow: {flow_id}")
                    # Forward the packet
                    self._handle_authenticated_packet(datapath, msg, in_port, src_mac, dst_mac)
                else:
                    self.logger.info(f"Zero Trust: Denied flow: {flow_id}")
                    # Drop the packet (by not installing flow rules)
                    return
            else:
                # Connection already authenticated, handle normally
                self._handle_authenticated_packet(datapath, msg, in_port, src_mac, dst_mac)
    
    def _handle_authenticated_packet(self, datapath, msg, in_port, src_mac, dst_mac):
        """Handle packets from authenticated flows"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Learn MAC address to avoid flooding
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        
        # If destination MAC is known, forward to the correct port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # Construct action
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            # Set short timeouts to enforce frequent re-authentication
            self.add_flow(datapath, 1, match, actions, idle_timeout=60, hard_timeout=300)
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

def main():
    from ryu.cmd import manager
    manager.main()

if __name__ == '__main__':
    main()
