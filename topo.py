from mininet.topo import Topo 

class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        # add hosts
        pc1 = self.addHost('pc1', ip='192.168.1.10/24' )
        pc2 = self.addHost('pc2',ip='192.168.1.11/24' )
        pc3 = self.addHost('pc3',ip='192.168.1.12/24' )
        pc4 = self.addHost('pc4',ip='192.168.1.13/24' )
        internet_pc = self.addHost('pc5',ip='192.168.1.254/24') #internet pc
        db_server = self.addHost('h2',ip='192.168.1.51/24') #db server
        web_server = self.addHost('h1',ip='192.168.1.50/24' ) #web server
        # add switches
        server_farm = self.addSwitch('s1')#site 1 server farm
        site1 = self.addSwitch('s2')#site1
        edge = self.addSwitch('s3')#edge
        site2 = self.addSwitch('s4')#site2
        # add links 
        self.addLink(pc1, site1)
        self.addLink(pc2, site1)
        self.addLink(pc3, site2)
        self.addLink(pc4, site2)
        self.addLink(internet_pc, edge)
        self.addLink(db_server, server_farm)
        self.addLink(web_server, server_farm)
        self.addLink(server_farm, site1)
        self.addLink(site1, edge)
        self.addLink(edge, site2)

topos = {'c_topo':(lambda:MyTopo())}
        