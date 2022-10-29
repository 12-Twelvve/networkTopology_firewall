#!/usr/bin/python		
	
from mininet.topo import Topo		
from mininet.net import Mininet		
from mininet.util import dumpNodeConnections		
from mininet.log import setLogLevel		
		
class MyFirstTopo( Topo ):		
    "Simple topology example."		
    def __init__( self ):		
        "Create custom topo."		
        # Initialize topology		
        Topo.__init__( self )		
        # Add hosts and switches		
        h1 = self.addHost( 'h1' )		
        h2 = self.addHost( 'h2' )		
        h3 = self.addHost( 'h3' )		
        h4 = self.addHost( 'h4' )		
        leftSwitch = self.addSwitch( 's1' )		
        rightSwitch = self.addSwitch( 's2' )		
        # Add links		
        self.addLink( h1, leftSwitch )		
        self.addLink( h2, leftSwitch )		
        self.addLink( leftSwitch, rightSwitch )		
        self.addLink( rightSwitch, h3 )		
        self.addLink( rightSwitch, h4 )		

def runExperiment():		
    "Create and test a simple experiment"		
    topo = MyFirstTopo( )		
    net = Mininet(topo)		
    net.start()		
    print( "Dumping host connections")		
    dumpNodeConnections(net.hosts)		
    print( "Testing network connectivity")		
    net.pingAll()		
    net.stop()		
 		
if __name__ == '__main__':		
    # Tell mininet to print useful information		
    setLogLevel('info')		
    runExperiment()