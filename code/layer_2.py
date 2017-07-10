import struct
from binascii import *


class Ether :

  def __init__ (self,data):
    self.e_head = struct.unpack("!6s6sH", data)
    self.e_dst = hexlify(self.e_head[0])
    self.e_src = hexlify(self.e_head[1])
   
    self.pdic = {2048:'IP', 2054:'ARP'}
    try:
      self.e_pro = self.pdic[self.e_head[2]]
    except:
      self.e_pro = "Others "+ str(self.e_head[2])+'('+str(hex(self.e_head[2]))+')'

  def edata(self):
    print "<========================= Ethernet Header ==========================> \n"
    print "     Source MAC: %s:%s:%s:%s:%s:%s" %(self.e_src[0:2],self.e_src[2:4],self.e_src[4:6],self.e_src[6:8],self.e_src[8:10],self.e_src[10:12]) 
    print "     Destination Mac: %s:%s:%s:%s:%s:%s" %(self.e_dst[0:2],self.e_dst[2:4],self.e_dst[4:6],self.e_dst[6:8],self.e_dst[8:10],self.e_dst[10:12])
    print "     Protocol: %s" %(self.e_pro)
  

