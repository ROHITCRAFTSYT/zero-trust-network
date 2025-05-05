#!/usr/bin/python

"""
Zero Trust Network Prototype using SDN principles
Implemented with Mininet, OpenFlow protocol, and Ryu controller
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def createZeroTrustNetwork():
    """
    Create a zero-trust network topology using Mininet
    """
    # Create network with remote controller
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
    
    # Add a remote controller (Ryu)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    # Create switches for different segments
    trusted_switch = net.addSwitch('s1')      # Trusted zone
    dmz_switch = net.addSwitch('s2')          # DMZ zone
    untrusted_switch = net.addSwitch('s3')    # Untrusted zone
    
    # Create shared infrastructure switches
    core_switch = net.addSwitch('s4')         # Core switch connecting all zones
    
    # Create hosts in trusted zone
    trusted_host1 = net.addHost('h1', ip='10.0.1.2/24', mac='00:00:00:00:01:02')
    trusted_host2 = net.addHost('h2', ip='10.0.1.3/24', mac='00:00:00:00:01:03')
    
    # Create hosts in DMZ
    dmz_server1 = net.addHost('h3', ip='10.0.2.2/24', mac='00:00:00:00:02:02')  # Web server
    dmz_server2 = net.addHost('h4', ip='10.0.2.3/24', mac='00:00:00:00:02:03')  # Database server
    
    # Create hosts in untrusted zone
    untrusted_host = net.addHost('h5', ip='10.0.3.2/24', mac='00:00:00:00:03:02')
    
    # Add authentication server - critical for zero-trust
    auth_server = net.addHost('auth', ip='10.0.4.2/24', mac='00:00:00:00:04:02')
    
    # Add policy server - manages access policies
    policy_server = net.addHost('policy', ip='10.0.4.3/24', mac='00:00:00:00:04:03')
    
    # Connect all zone switches to the core switch
    net.addLink(trusted_switch, core_switch, bw=100)
    net.addLink(dmz_switch, core_switch, bw=100)
    net.addLink(untrusted_switch, core_switch, bw=100)
    
    # Connect hosts to their respective switches
    net.addLink(trusted_host1, trusted_switch)
    net.addLink(trusted_host2, trusted_switch)
    net.addLink(dmz_server1, dmz_switch)
    net.addLink(dmz_server2, dmz_switch)
    net.addLink(untrusted_host, untrusted_switch)
    
    # Connect authentication and policy servers to core switch
    net.addLink(auth_server, core_switch)
    net.addLink(policy_server, core_switch)
    
    # Start the network
    net.build()
    c0.start()
    for switch in [trusted_switch, dmz_switch, untrusted_switch, core_switch]:
        switch.start([c0])
    
    # Configure default gateways
    trusted_host1.cmd('route add default gw 10.0.1.1')
    trusted_host2.cmd('route add default gw 10.0.1.1')
    dmz_server1.cmd('route add default gw 10.0.2.1')
    dmz_server2.cmd('route add default gw 10.0.2.1')
    untrusted_host.cmd('route add default gw 10.0.3.1')
    auth_server.cmd('route add default gw 10.0.4.1')
    policy_server.cmd('route add default gw 10.0.4.1')
    
    # Start auth server (simple HTTP server for simulation)
    auth_server.cmd('python -m SimpleHTTPServer 8080 &')
    
    # Start policy server (simple HTTP server for simulation)
    policy_server.cmd('python -m SimpleHTTPServer 8081 &')
    
    # Print network information
    info('*** Network topology is ready\n')
    info('*** Run your Ryu controller with the zero_trust_controller.py script\n')
    
    # Start CLI
    CLI(net)
    
    # Clean up when done
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    createZeroTrustNetwork()
