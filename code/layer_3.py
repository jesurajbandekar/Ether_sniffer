import struct
import socket
from binascii import *

class IP:

  def __init__(self,data):
    self.i_h = struct.unpack("!BBHHHBBH4s4s", data)
    self.ver = self.i_h[0] >> 4 #to get the first 4 bits
    self.ihl = self.i_h[0] & 0xf #to get the last 4 bits
    self.tl = self.i_h[2] 
    self.ttl = self.i_h[5]
    self.pro = self.i_h[6]
    self.hc = self.i_h[7]
    self.i_src = socket.inet_ntoa(self.i_h[8])
    self.i_dst = socket.inet_ntoa(self.i_h[9])

  def idis(self):
    print "  <========================== IP ==========================>"
    print "      IP Version : {}".format(self.ver) 
    print "      Header Length: {}".format(self.ihl)
    print "      Time to live : {}".format(self.ttl)
    print "      Protocol: {}".format (self.pro)   
    print "      Source IP: {}".format(self.i_src)
    print "      Destination IP: {} ".format(self.i_dst)


class ARP:

  def __init__(self,data):
    self.data = data
    self.ah = struct.unpack("!HHBBH6s4s6s4s", self.data)    
    self.pt = self.ah[1]
    self.hln = self.ah[2]
    self.pln = self.ah[3]
    self.sha = hexlify(self.ah[5])
    self.spa = self.ah[6]
    self.tha = hexlify(self.ah[7])
    self.tpa = self.ah[8]

    self.tydic = {1:'Ethernet(10Mb)',6:'IEEE 802 Networks', 7:'ARCNET', 15:'Frame Relay', 16:'Asyncronous Transfer Mode(16)', 17:'HDLC',18:'FFibre Channel', 19:'Asynchronous Tranfer Mode(19)', 20:'Serial Line'}
    try:
      self.hwt = self.tydic[self.ah[0]]  
    except :
      self.hwt = "Others " + str(self.ah[0])

    self.opdic = {1:'ARP Request', 2:'ARP Reply', 3:'RARP Request', 4:'RARP Reply', 5:'DRARP Request', 6:'DRARP Reply', 7:'DRARP Error', 8:'InARP Request', 9:'InARP Reply'}
    try:
      self.op = self.opdic[self.ah[4]]
    except:
      self.op = "Others  " + str(self.ah[4])

  def adis(self):
    print "  <======================== ARP ============================> "
    print "    Hardware Type:  {}".format(self.hwt)
    print "    Operation:  {}".format(self.op)
    print "    Sender Hardware Address:  {}:{}:{}:{}:{}:{}".format(self.sha[0:2],self.sha[2:4],self.sha[4:6],self.sha[6:8],self.sha[8:10],self.sha[10:12])
    print "    Sender Protocol Address:  {}".format(socket.inet_ntoa(self.spa)) 
    print "    Target Hardware Address:  {}:{}:{}:{}:{}:{}".format(self.tha[0:2],self.tha[2:4],self.tha[4:6],self.tha[6:8],self.tha[8:10],self.tha[10:12])
    print"     Target Protocol Address:  {} \n\n".format(socket.inet_ntoa(self.tpa))
