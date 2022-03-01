const net = require('net');
const crypto = require('crypto');
const ip6addr = require('ip6addr');
const fs = require('fs');
const ed25519 = require('./ed25519.js')
const blake2 = require('blake2');
const {
    encodeAddress
} = require("./utils.js")

const config = require('./config.json')
const NodeSecret = crypto.randomBytes(64);
const NodePublic = ed25519.getPublicKey(NodeSecret);

console.log("Node Secret:", NodeSecret.toString("hex"))
console.log("Node ID:", encodeAddress(NodePublic, "node"))

function Hash64(input) {
    var hash = blake2.createHash('blake2b', {
        digestLength: 64
    }).update(input).digest()
    return hash;
}

function Hash32(input) {
    var hash = blake2.createHash('blake2b', {
        digestLength: 32
    }).update(input).digest()
    return hash;
}

var SecretKey = Hash64(
    Buffer.from(
        config.privateKey,
        "hex"
    )
);
var PublicKey = ed25519.getPublicKey(SecretKey);
console.log("Account:", encodeAddress(PublicKey, "nano"))

const RequestTypes = {
    0x00: "Invalid",
    0x01: "NaT",
    0x02: "KeepAlive",
    0x03: "Publish",
    0x04: "ConfirmReq",
    0x05: "ConfirmAck",
    0x06: "BulkPull",
    0x07: "BulkPush",
    0x08: "FrontierReq",
    0x0a: "NodeIDHandshake",
    0x0b: "BulkPullAccount",
    0x0c: "TelemetryReq",
    0x0d: "TelemetryAck",
}

function encodeIPv6(raw) {
    const hex = raw.toString("hex");
    const hexParts = hex.match(/.{1,4}/g);
    const subnet = hexParts[5];
    let formattedAddress = hexParts.join(":");
    return formattedAddress;
}

function decodeConnectionInfo(raw) {
    const address = encodeIPv6(raw.subarray(0, 16));
    const port = raw.readUInt16LE(16);
    return {
        address,
        port
    }
}

function encodeConnectionInfo(address, port) {
    const raw = Buffer.alloc(18);
    raw.set(ip6addr.parse(address).toBuffer())
    raw.writeUInt16LE(port, 16);
    return raw;
}

function encodeMessage(message, messageType, ext) {
    const messageLength = message.length;
    const packet = Buffer.alloc(8 + messageLength);
    packet[0] = 0x52;
    packet[1] = 0x43;
    packet[2] = 0x12;
    packet[3] = 0x12;
    packet[4] = 0x12;
    packet[5] = messageType;
    packet.writeUInt16LE(ext, 6);
    packet.set(message, 8)
    return packet;
}

function decodeMessage(packet) {
    if (packet[0] !== 0x52) return null;
    if (packet[1] !== 0x43) return null;
    if (packet[3] !== 0x12) return null;
    if (packet.length < 9) return null;
    const messageType = packet[5];
    const extensions = packet.readUInt16LE(6);
    const data = packet.slice(8);
    return {
        messageType,
        extensions,
        data
    }
}

function decodeNIH(packet, extensions) {
    let hasQuery = !!(extensions & 0x0001);
    let hasResponse = !!(extensions & 0x0002);
    const correctLength = (hasQuery && 32) + (hasResponse && 96);
    if (packet.length !== correctLength) return {};
    let query;
    let response;
    let extraPtr = 0;
    if (hasQuery) {
        query = packet.subarray(0, 32);
        extraPtr = 32;
    }
    if (hasResponse) {
        const responseX = packet.subarray(extraPtr, 96 + extraPtr);
        const account = responseX.subarray(0, 32);
        const signature = responseX.subarray(32, 96);
        response = {
            account,
            signature
        }
    }
    return {
        query,
        response
    }
}

const votePrefix = Buffer.from("vote ")
const DefaultTimestamp = Buffer.from("ff".repeat(8),"hex")

function encodeVACK(hashes) {
    const item_count = hashes.length;
    const extensions = item_count << 12 | 0x0100;
    const hashItemPtr = 32 * item_count;
    const packet = Buffer.alloc(104+hashItemPtr);
    const hashItems = Buffer.alloc(hashItemPtr);
    for (var i = 0; i < item_count; i++) {
        const hash = hashes[i];
        hashItems.set(hash,i*32);
    }
    const VoteHash = Hash32(Buffer.concat([
        votePrefix,
        hashItems,
        DefaultTimestamp
    ]));
    const Signature = ed25519.sign(
                        VoteHash,
                        SecretKey
                    );
    
    packet.set(PublicKey)
    packet.set(Signature,32)
    packet.set(DefaultTimestamp,96)
    packet.set(hashItems,104)

    return {packet,extensions}
}

function decodeVACK(packet, extensions) {
    const item_count = (extensions & 0xf000) >> 12;

    const account = packet.subarray(0, 32);
    const signature = packet.subarray(32, 96);
    const timestamp = packet.subarray(96, 104);

    const hashItemPtr = 104 + (32 * item_count);
    if (packet.length < hashItemPtr) return null;

    const hashItems = packet.subarray(104, hashItemPtr);
    const hashList = [];

    for (var i = 0; i < item_count; i++) {
        const hashPtr = 32 * i;
        hashList.push(hashItems.subarray(hashPtr, hashPtr + 32));
    }
    const VoteHash = Hash32(Buffer.concat([
        votePrefix,
        hashItems,
        timestamp
    ]));
    const isValid = ed25519.verify(signature,VoteHash,account)
    return {
        account,
        signature,
        timestamp,
        hashList,
        isValid
    }
}

function decodeVREQ(packet, extensions) {
    const item_count = (extensions & 0xf000) >> 12;
    const hashItemPtr = (64 * item_count);
    if (packet.length < hashItemPtr) return null;

    const hashItems = packet.subarray(0, hashItemPtr);
    const BlockSector = packet.subarray(hashItemPtr);
    const hashList = [];

    for (var i = 0; i < item_count; i++) {
        const hashPtr = 64 * i;
        const first = hashItems.subarray(hashPtr, hashPtr + 32);
        const second = hashItems.subarray(hashPtr + 32, hashPtr + 64);
        //hashList.push({first,second});
        hashList.push(first)
        //hashList.push(second)
    }

    //console.log("BlockSector",BlockSector.length)

    return {hashList,BlockSector}
}

function encodeVREQ(hashes) {
    const item_count = hashes.length;
    const extensions = item_count << 12 | 0x0100;
    const hashItemPtr = 64 * item_count;
    const hashItems = Buffer.alloc(hashItemPtr);
    for (var i = 0; i < item_count; i++) {
        const hash = hashes[i];
        hashItems.set(Buffer.concat([hash.first,hash.second]),i*64);
    }

    return {packet:hashItems,extensions}
}

const defaultPeers = Buffer.from("00".repeat(18),"hex")

var peerList = [];

var connectedPeers = {};

let CPeerID = 0;

function getRandomPeers() {
    const shuffled = Object.values(connectedPeers).sort(() => 0.5 - Math.random());
    let selected = shuffled.slice(0, 8).map(x=>x.connectionData);
    return selected;
}

class NanoConnection {
    constructor(address, port, connectionData) {
        const self = this;

        this.connectionData = connectionData;
        
        this.peerID = CPeerID++;
        this.NodeID = null;
        this.HasResponse = false;
        this.cookie = crypto.randomBytes(32);

        const NodeIDMessage = encodeMessage(this.cookie, 0x0a, 1)

        this.client = net.createConnection({
            port: port,
            host: address
        }, () => {
            self.client.write(NodeIDMessage);
        });
        this.client.on("data", (data) => {
            self.handleMessage(data)
        })
        this.client.on("close", () => {
            delete connectedPeers[this.peerID];
            if (this.NodeID) {
                console.log(Object.values(connectedPeers).length)
            }
        })
        this.client.on("error", () => {
        })
    }
    sendMessage(msgType, msg, extensions) {
        this.client.write(encodeMessage(msg, msgType, extensions))
    }
    close() {
        this.client.destroy();
    }
    keepalive() {
        const peerListXA = getRandomPeers();
        this.sendMessage(0x02, Buffer.concat(peerListXA,144), 0)
    }
    handleMessage(packet) {
        const packetInfo = decodeMessage(packet)
        if (packetInfo == null) {
            this.close();
            return;
        }
        const {
            data,
            extensions
        } = packetInfo;
        switch (RequestTypes[packetInfo.messageType]) {
            case "NodeIDHandshake": {
                const NIHData = decodeNIH(data, extensions);
                let responseData;
                if (NIHData.query && !this.HasResponse) {
                    this.HasResponse = true;
                    const Signature = ed25519.sign(
                        NIHData.query,
                        NodeSecret
                    );
                    responseData = Buffer.concat([
                        NodePublic,
                        Signature
                    ]);
                }
                if (NIHData.response && !this.NodeID) {
                    const Resposne = NIHData.response;
                    const account = Resposne.account;
                    const signature = Resposne.signature;
                    const validation = ed25519.verify(
                        signature,
                        this.cookie,
                        account
                    );
                    if (!validation) return;
                    this.NodeID = account;
                    connectedPeers[this.peerID] = {connectionData:this.connectionData,socket:this.client}
                    console.log(Object.values(connectedPeers).length)
                    const vREQ = encodeVREQ([{first:Buffer.from("1C7153ACED1B3AE556EF973D6B3ACFE8EF67AE04DFE8B95BA57F1B29817C2DC2","hex"),second:Buffer.from("9A3E62F7A8C9DDE2C2EE8D4C6BEC488A26F5EA37572D519023F3F40E7F24E427","hex")}])
                    
                    setTimeout(()=>{
                        this.sendMessage(0x04,vREQ.packet,vREQ.extensions)
                        this.sendMessage(0x0c,Buffer.from([]),0)
                    },1000)
                    setInterval(() => {
                        this.keepalive()
                    }, 1000)
                }
                if (responseData) {
                    this.sendMessage(
                        0x0a,
                        responseData,
                        2
                    )
                }
                break;
            }
            case "KeepAlive": {
                const peers = Math.floor(data.length/18)
                for (var i = 0; i < peers; i++) {
                    const peerPtr = i*18
                    const peer = data.subarray(
                        peerPtr,
                        peerPtr+18
                    );
                    const peerBinary = peer.toString("binary")
                    if (peerList.includes(peerBinary)) continue;
                    peerList.push(peerBinary)
                    addConnection(peer)
                }
                break;
            }
            case "ConfirmReq": {
                const VData = decodeVREQ(data, extensions)
                const mappedData = VData.hashList//.map(x=>x.first)
                const vACK = encodeVACK(mappedData)
                /*setTimeout(()=>{
                    this.sendMessage(
                        0x05,
                        Buffer.concat([vACK.packet,VData.BlockSector]),
                        vACK.extensions
                    )
                },100)*/
                break;
            }
            case "ConfirmAck": {
                //console.log(extensions.toString(16))
                const VData = decodeVACK(data, extensions);
                if (VData == null) return;
                //console.log(VData)
                break;
            }
            case "TelemetryReq": {
                this.sendMessage(
                        0x0d,
                        Buffer.from([]),
                        0
                )
                break;
            }
            case "TelemetryAck": {
                break;
            }
            default: {
                //console.log(RequestTypes[packetInfo.messageType])
            }
        }
    }
}

function addConnection(rawConnectionInfo) {
    const connectionInfo = decodeConnectionInfo(
        rawConnectionInfo
    );
    try {
        new NanoConnection(
            connectionInfo.address,
            connectionInfo.port,
            rawConnectionInfo
        )
    } catch (e) {
        console.log(e)
    }
}

const peerInfo = config.defaultPeer;
const defaultConnectionInfo = encodeConnectionInfo(
    peerInfo[0],
    peerInfo[1]
);

addConnection(defaultConnectionInfo)
