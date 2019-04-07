/* !
* noise.js - peer-to-peer communication encryption.
* Copyright (c) 2019, YusukeShimizu (MIT License).
 * Resources:
 *   https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md
 *
 * Parts of this software are based on LND and hsd:
 *   Copyright (C) 2015-2017 The Lightning Network Developers
 *   https://github.com/lightningnetwork/lnd/blob/master/brontide/noise.go
 *   https://github.com/lightningnetwork/lnd/blob/master/brontide/noise_test.go
 *   brontide.js - peer-to-peer communication encryption.
 *   Copyright (c) 2018, Christopher Jeffrey (MIT License).
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const sha256 = require('bcrypto/lib/sha256');
const aead = require('bcrypto/lib/aead');
const hkdf = require('bcrypto/lib/hkdf');
const secp256k1 = require('bcrypto/lib/secp256k1');

/*
 * Constants
 */

const ZERO_KEY = Buffer.alloc(32, 0x00);
const ZERO_PUB = Buffer.alloc(33, 0x00);
const EMPTY = Buffer.alloc(0);

const PROTOCOL_NAME = 'Noise_XK_secp256k1_ChaChaPoly_SHA256';
const PROLOGUE = 'hns';
const ROTATION_INTERVAL = 1000;
const VERSION = 0;
const ACT_ONE_SIZE = 50;
const ACT_TWO_SIZE = 50;
const ACT_THREE_SIZE = 66;

/**
 * CipherState
 * @extends {EventEmitter}
 */

class CipherState extends EventEmitter {
  constructor() {
    super();
    this.nonce = 0;
    this.iv = Buffer.alloc(12, 0x00);
    this.key = ZERO_KEY; // secret key
    this.salt = ZERO_KEY;
  }

  update() {
    this.iv.writeUInt32LE(this.nonce, 4, true);
    return this.iv;
  }

  initKey(key) {
    assert(Buffer.isBuffer(key));
    this.key = key;
    this.nonce = 0;
    this.update();
    return this;
  }

  initSalt(key, salt) {
    assert(Buffer.isBuffer(salt));
    this.salt = salt;
    this.initKey(key);
    return this;
  }

  rotateKey() {
    const info = EMPTY;
    const old = this.key;
    const [salt, next] = expand(old, this.salt, info);

    this.salt = salt;
    this.initKey(next);

    return this;
  }

  encrypt(pt, ad) {
    const tag = aead.encrypt(this.key, this.iv, pt, ad);

    this.nonce += 1;
    this.update();

    if (this.nonce === ROTATION_INTERVAL) {
      this.rotateKey();
    }

    return tag;
  }

  decrypt(ct, tag, ad) {
    if (!aead.decrypt(this.key, this.iv, ct, tag, ad)) {
      return false;
    }

    this.nonce += 1;
    this.update();

    if (this.nonce === ROTATION_INTERVAL) {
      this.rotateKey();
    }

    return true;
  }
}

/**
 * SymmetricState
 * @extends {CipherState}
 */

class SymmetricState extends CipherState {
  constructor() {
    super();
    this.chain = ZERO_KEY; // chaining key
    this.temp = ZERO_KEY; // temp key
    this.digest = ZERO_KEY; // handshake digest
  }

  initSymmetric(protocolName) {
    assert(typeof protocolName === 'string');

    const empty = ZERO_KEY;
    const proto = Buffer.from(protocolName, 'ascii');

    this.digest = sha256.digest(proto);
    this.chain = this.digest;
    this.initKey(empty);

    return this;
  }

  mixKey(input) {
    const info = EMPTY;
    const secret = input;
    const salt = this.chain;

    [this.chain, this.temp] = expand(secret, salt, info);

    this.initKey(this.temp);

    return this;
  }

  mixDigest(data, tag) {
    return sha256.multi(this.digest, data, tag);
  }

  mixHash(data, tag) {
    this.digest = this.mixDigest(data, tag);
    return this;
  }

  encryptHash(pt) {
    const tag = this.encrypt(pt, this.digest);
    this.mixHash(pt, tag);
    return tag;
  }

  decryptHash(ct, tag) {
    assert(Buffer.isBuffer(tag));

    const digest = this.mixDigest(ct, tag);

    if (!this.decrypt(ct, tag, this.digest)) {
      return false;
    }

    this.digest = digest;

    return true;
  }
}

/**
 * HandshakeState
 * @extends {SymmetricState}
 */

class HandshakeState extends SymmetricState {
  constructor() {
    super();
    this.initiator = false;
    this.localStatic = ZERO_KEY;
    this.localEphemeral = ZERO_KEY;
    this.remoteStatic = ZERO_PUB;
    this.remoteEphemeral = ZERO_PUB;
    this.generateKey = () => secp256k1.privateKeyGenerate();
  }

  initState(initiator, prologue, localPub, remotePub) {
    assert(typeof initiator === 'boolean');
    assert(typeof prologue === 'string');
    assert(Buffer.isBuffer(localPub));
    assert(!remotePub || Buffer.isBuffer(remotePub));

    this.initiator = initiator;
    this.localStatic = localPub; // private
    this.remoteStatic = remotePub || ZERO_PUB;

    this.initSymmetric(PROTOCOL_NAME);
    this.mixHash(Buffer.from(prologue, 'ascii'));

    if (initiator) {
      this.mixHash(remotePub);
    } else {
      const pub = getPublic(localPub);
      this.mixHash(pub);
    }

    return this;
  }
}

/**
 * Noise
 * @extends {HandshakeState}
 */

class Noise extends HandshakeState {
  constructor() {
    super();
    this.sendCipher = new CipherState();
    this.recvCipher = new CipherState();
  }

  init(initiator, localPub, remotePub) {
    return this.initState(initiator, PROLOGUE, localPub, remotePub);
  }

  genActOne() {
    // e
    this.localEphemeral = this.generateKey();

    const ephemeral = getPublic(this.localEphemeral);
    this.mixHash(ephemeral);

    // es
    const s = ecdh(this.remoteStatic, this.localEphemeral);
    this.mixKey(s);

    const tag = this.encryptHash(EMPTY);

    const actOne = Buffer.allocUnsafe(ACT_ONE_SIZE);
    actOne[0] = VERSION;
    ephemeral.copy(actOne, 1);
    tag.copy(actOne, 34);

    return actOne;
  }

  recvActOne(actOne) {
    assert(Buffer.isBuffer(actOne));

    if (actOne.length !== ACT_ONE_SIZE) {
      throw new Error('Act one: bad size.');
    }

    if (actOne[0] !== VERSION) {
      throw new Error('Act one: bad version.');
    }

    const e = actOne.slice(1, 34);
    const p = actOne.slice(34);

    if (!secp256k1.publicKeyVerify(e)) {
      throw new Error('Act one: bad key.');
    }

    // e
    this.remoteEphemeral = e;
    this.mixHash(this.remoteEphemeral);

    // es
    const s = ecdh(this.remoteEphemeral, this.localStatic);
    this.mixKey(s);

    if (!this.decryptHash(EMPTY, p)) {
      throw new Error('Act one: bad tag.');
    }

    return this;
  }

  genActTwo() {
    // e
    this.localEphemeral = this.generateKey();

    const ephemeral = getPublic(this.localEphemeral);
    this.mixHash(ephemeral);

    // ee
    const s = ecdh(this.remoteEphemeral, this.localEphemeral);
    this.mixKey(s);

    const tag = this.encryptHash(EMPTY);

    const actTwo = Buffer.allocUnsafe(ACT_TWO_SIZE);
    actTwo[0] = VERSION;
    ephemeral.copy(actTwo, 1);
    tag.copy(actTwo, 34);

    return actTwo;
  }

  recvActTwo(actTwo) {
    assert(Buffer.isBuffer(actTwo));

    if (actTwo.length !== ACT_TWO_SIZE) {
      throw new Error('Act two: bad size.');
    }

    if (actTwo[0] !== VERSION) {
      throw new Error('Act two: bad version.');
    }

    const e = actTwo.slice(1, 34);
    const p = actTwo.slice(34);

    if (!secp256k1.publicKeyVerify(e)) {
      throw new Error('Act two: bad key.');
    }

    // e
    this.remoteEphemeral = e;
    this.mixHash(this.remoteEphemeral);

    // ee
    const s = ecdh(this.remoteEphemeral, this.localEphemeral);
    this.mixKey(s);

    if (!this.decryptHash(EMPTY, p)) {
      throw new Error('Act two: bad tag.');
    }

    return this;
  }

  genActThree() {
    const ourPubkey = getPublic(this.localStatic);
    const tag1 = this.encryptHash(ourPubkey);
    const ct = ourPubkey;

    const s = ecdh(this.remoteEphemeral, this.localStatic);
    this.mixKey(s);

    const tag2 = this.encryptHash(EMPTY);

    const actThree = Buffer.allocUnsafe(ACT_THREE_SIZE);
    actThree[0] = VERSION;
    ct.copy(actThree, 1);
    tag1.copy(actThree, 34);
    tag2.copy(actThree, 50);

    this.split();

    return actThree;
  }

  recvActThree(actThree) {
    assert(Buffer.isBuffer(actThree));

    if (actThree.length !== ACT_THREE_SIZE) {
      throw new Error('Act three: bad size.');
    }

    if (actThree[0] !== VERSION) {
      throw new Error('Act three: bad version.');
    }

    const s1 = actThree.slice(1, 34);
    const p1 = actThree.slice(34, 50);

    const s2 = actThree.slice(50, 50);
    const p2 = actThree.slice(50, 66);

    // s
    if (!this.decryptHash(s1, p1)) {
      throw new Error('Act three: bad tag.');
    }

    const remotePub = s1;

    if (!secp256k1.publicKeyVerify(remotePub)) {
      throw new Error('Act three: bad key.');
    }

    this.remoteStatic = remotePub;

    // se
    const se = ecdh(this.remoteStatic, this.localEphemeral);
    this.mixKey(se);

    if (!this.decryptHash(s2, p2)) {
      throw new Error('Act three: bad tag.');
    }

    this.split();

    return this;
  }

  split() {
    const [h1, h2] = expand(EMPTY, this.chain, EMPTY);

    if (this.initiator) {
      const sendKey = h1;
      this.sendCipher.initSalt(sendKey, this.chain);
      const recvKey = h2;
      this.recvCipher.initSalt(recvKey, this.chain);
    } else {
      const recvKey = h1;
      this.recvCipher.initSalt(recvKey, this.chain);
      const sendKey = h2;
      this.sendCipher.initSalt(sendKey, this.chain);
    }

    return this;
  }

  write(data) {
    assert(Buffer.isBuffer(data));
    assert(data.length <= 0xffff);

    const packet = Buffer.allocUnsafe(2 + 16 + data.length + 16);
    packet.writeUInt16BE(data.length, 0);
    data.copy(packet, 2 + 16);

    const len = packet.slice(0, 2);
    const ta1 = packet.slice(2, 18);
    const msg = packet.slice(18, 18 + data.length);
    const ta2 = packet.slice(18 + data.length, 18 + data.length + 16);

    const tag1 = this.sendCipher.encrypt(len);
    tag1.copy(ta1, 0);

    const tag2 = this.sendCipher.encrypt(msg);
    tag2.copy(ta2, 0);

    return packet;
  }

  read(packet) {
    assert(Buffer.isBuffer(packet));

    const len = packet.slice(0, 2);
    const ta1 = packet.slice(2, 18);

    if (!this.recvCipher.decrypt(len, ta1)) {
      throw new Error('Bad tag for header.');
    }

    const size = len.readUInt16BE(0, true);
    assert(packet.length === 18 + size + 16);

    const msg = packet.slice(18, 18 + size);
    const ta2 = packet.slice(18 + size, 18 + size + 16);

    if (!this.recvCipher.decrypt(msg, ta2)) {
      throw new Error('Bad tag for message.');
    }

    return msg;
  }
}

/*
 * Helpers
 */

function ecdh(publicKey, privateKey) {
  const secret = secp256k1.derive(publicKey, privateKey, true);
  return sha256.digest(secret);
}

function getPublic(priv) {
  return secp256k1.publicKeyCreate(priv, true);
}

function expand(secret, salt, info) {
  const prk = hkdf.extract(sha256, secret, salt);
  const out = hkdf.expand(sha256, prk, info, 64);
  return [out.slice(0, 32), out.slice(32, 64)];
}

/*
 * Expose
 */

exports.CipherState = CipherState;
exports.SymmetricState = SymmetricState;
exports.HandshakeState = HandshakeState;
exports.Noise = Noise;
