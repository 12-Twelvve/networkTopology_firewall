#! usr/bin/env python
import copy

class parse_firewall:    
    def parse(self):
        firewall_file = open("rules.txt")
        list1 = []
        firewall_dict = {}
        listobj = []
        lines = [line.strip() for line in firewall_file]
        for i in range(len(lines)):
            list1.append(lines[i].split(',')) 
            list2 = copy.deepcopy(list1)
            if not(str(list2[i][0]) in firewall_dict): #false
                key = str(list2[i][0])
                list2[i].remove(key)
                tup = tuple(list2[i])
                listobj.append(tup)
                tup = tuple(listobj)
                firewall_dict[key] = tup
                
            elif (str(list2[i][0]) in firewall_dict): #true
                key = str(list2[i][0])
                dst = firewall_dict[key]
                dst = list(dst)
                list2[i].remove(key)
                dst.append(tuple(list2[i]))
                tup = tuple(dst)
                firewall_dict[key] = tup
            del listobj[:] 
        # print(firewall_dict.keys())
        print(firewall_dict)
        return firewall_dict

pfire = parse_firewall()
pfire.parse()


# --------------------------------
val = {
   '10.0.0.1': (
        ('10.0.0.2', 'TCP', '1000', '8080', 'NEW', 'ALLOW'), 
        ('10.0.0.3', 'TCP', '1000', '8080', 'NEW', 'ALLOW'), 
        ('10.0.0.2', 'UDP', '1000', '8080', '-', 'ALLOW'), 
        ('10.0.0.3', 'UDP', '1000', '8080', '-', 'ALLOW'), 
        ('10.0.0.2', 'ICMP', '-', '-', 'PING', 'ALLOW')
        ), 
   '10.0.0.2': (
        ('10.0.0.3', 'TCP', '1000', '1000', 'NEW', 'ALLOW'), 
        ('10.0.0.1', 'TCP', '8080', '1000', 'EST', 'ALLOW'), 
        ('10.0.0.3', 'TCP', '1000', '1000', 'EST', 'ALLOW'),
        ('10.0.0.1', 'UDP', '8080', '1000', '-', 'ALLOW'), 
        ('10.0.0.3', 'UDP', '1000', '1000', '-', 'ALLOW')
        ),
   '10.0.0.3': (
        ('10.0.0.2', 'TCP', '1000', '1000', 'EST', 'ALLOW'), 
        ('10.0.0.2', 'TCP', '1000', '1000', 'NEW', 'ALLOW'), 
        ('10.0.0.1', 'TCP', '8080', '1000', 'EST', 'ALLOW'), 
        ('10.0.0.1', 'UDP', '8080', '1000', '-', 'ALLOW'), 
        ('10.0.0.2', 'UDP', '1000', '1000', '-', 'ALLOW')
        ), 
}
#  if ((temp[i][0]==ipp.dst) and (temp[i][1]=='ANY') and (temp[i][4]=='ANY') and (temp[i][5]=='ALLOW')):
#     flag = True #full access
#     break

# elif((temp[i][0]==ipp.dst)and (temp[i][1]=='TCP') and tcppkt and (temp[i][5]=='ALLOW')):
#     if (int(temp[i][3])==tcpp.dst_port) or (int(temp[i][2])==tcpp.src_port):   
#         flag = True #http only 
#         break
