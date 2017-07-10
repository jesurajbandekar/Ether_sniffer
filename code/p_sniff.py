from layer_2 import * 
from layer_3 import *
import sys


sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
 

while True: 

  try:
    data = sock.recv(65535)

    e_ob = Ether(data[0:14])
    e_ob.edata()

    if(e_ob.e_pro == 'IP'):
       i_ob = IP(data[14:34])
       i_ob.idis()
  
    elif(e_ob.e_pro == 'ARP'):
      a_ob = ARP(data[14:42])
      a_ob.adis()
  
  except KeyboardInterrupt:
    print "Done Scanning"
    sock.close()
    break
  
