import struct

class TCP :
 
  def __init__(self,data):
    self.th = struct.unpack("!HHLLHHHH", data)
    self.s_port = self.th[0]
    self.d_port = self.th[1]
    self.seq = self.th[2]
    self.ack = self.th[3]
    self.doff = self.th[4] >> 12
    self.res = (self.th[4] >> 6) & 0x3f
    self.flags = self.th[4] & 0x3f
    self.win = self.th[5]
    self.csum = self.th[6]
    self.uptr = self.th[7]


  def disp(self):
    print "    <====================TCP====================>"
    print "      Source Port: {}".format(self.s_port)
    print "      Destination Port: {}".format(self.d_port)
    print "      Sequence Number: {}".format(self.seq)
    print "      Acknowledgement Number: {}".format(self.ack)
    print "      Data Offset: {}".format(self.doff)
    print "      Reserved: {}".format(self.res)
    print "      Flags => URG: " + str(self.flags>> 5) +  ",ACK: " + str((self.flags>> 4)& 0x1) + ",PSH: " + str((self.flags >> 3) & 0x1) +  ",RST: " + str((self.flags >> 2) & 0x12) +  ",SYN: " + str((self.flags >> 1)&0x1) + ",FIN: " + str(self.flags & 0x1)
    print "      Window: {}".format(self.win)
    print "      Checksum: {}".format(self.csum)
    print "      Urgent Pointer: {}".format(self.uptr)


    
class UDP:

  def __init__(self,data):
    self.uh = struct.unpack("!HHHH",data)
    self.s_port = self.uh[0]
    self.d_port = self.uh[1]
    self.len = self.uh[2]
    self.csum = self.uh[3]

  def disp(self):
    print "    <===================UDP====================>"
    print "      Source Port: {}".format(self.s_port)
    print "      Destination Port: {}".format(self.d_port)
    print "      Length of UDP Packet: {}".format(self.len)
    print "      Checksum: {}".format(self.csum)


class ICMP:

  def __init__(self,data):
    self.cmph = struct.unpack("!HHL",data)
    self.type = self.cmph[0] >> 8
    self.code = self.cmph[0] & 0xff
    self.csum = self.cmph[1]
    self.roh = self.cmph[2]
    

  def disp(self):
    print "    <====================ICMP=====================>"
    if self.type == 0:
      print "      Echo Reply (Ping, type 0)"
    elif self.type == 1 or self.type == 2 or self.type== 3:
      if self.code == 0:
        print "      Destination Network Unreachable (code 0)"
      elif self.code == 1:
        print "      Destination Host Unreachable (code 1)"
      elif self.code == 2:
        print "      Destination Protocol Unreachable (code 2)"
      elif  self.code == 3:
        print "      Destination Port Unreachable (code 3) "
      elif self.code == 4:
        print "      Fragmentation Required and DF Flag set (code 4)"
      elif self.code == 5:
        print "      Source Route Failed (code 5)"
      elif self.code == 6:
        print "      Destination Network Unknown (code 6)"
      elif self.code == 7:
        print "      Destination Host Unknown (code 7)"
      elif self.code ==8:
        print "      Source Host Isolated (code 8)"
      elif self.code == 9:
        print "      Network Administratively Prohibited (code 9)"
      elif self.code == 10:
        print "      Host Administratively Prohibited (code 10)"
      elif self.code == 11:
        print "      Network Unreachable for ToS (code 11)"
      elif self.code == 12:
        print "      Host Unreachable for ToS (code 12)"
      elif self.code == 13:
        print "      Communication Admnistratively Prohibited (code 12)"
      elif self.code == 14:
        print "      Host Precedence Violation (code 14)"
      elif self.code == 15:
        print "      Precedence cutoff in effect (code 15)"
    elif self.type == 4:
      if  self.code == 0:
        print "      Source Quench (congestion control, code 0)"
    elif self.type == 5:
      if self.code == 0:
        print "      Redirect Datagram for the Network (code 0)"
      elif self.code == 1:
        print "      Redirect Datagram for the Host (code 1)"
      elif self.code == 2:
        print "      Redirect Datagram for the ToS and Network (code 2)"
      elif self.code == 3:
        print "      Redirect Datagram for the ToS and Host (code 3)"
    elif self.type == 6:
      print "      Alternate Host Address (type 6)"
    elif self.type == 8:
      print "      Echo Request (type 8)"
    elif self.type == 9:
      print "      Router Advertisement (type 9)"
    elif self.type == 10:
      print "      Router Discovery (type 10)"
    elif self.type == 11:
      if self.code == 0:
        print "      TTL expired in transit"
      elif self.code == 1:
        print "      Fragment reassembly time exceeded"
    else :
      print "      Type:{} , Code: {}".format(self.type,self.code)
