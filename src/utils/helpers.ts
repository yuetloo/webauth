import { encode } from "./base64url";

export function bufferToString(buff: ArrayBuffer) {
  const enc = new TextDecoder(); // always utf-8
  return enc.decode(buff);
}

function getEndian() {
  const arrayBuffer = new ArrayBuffer(2);
  const uint8Array = new Uint8Array(arrayBuffer);
  const uint16array = new Uint16Array(arrayBuffer);
  uint8Array[0] = 0xaa; // set first byte
  uint8Array[1] = 0xbb; // set second byte

  if (uint16array[0] === 0xbbaa) return "little";
  else return "big";
}

function readBE16(buffer: any) {
  if (buffer.length !== 2) throw new Error("Only 2byte buffer allowed!");

  if (getEndian() !== "big") buffer = buffer.reverse();

  return new Uint16Array(buffer.buffer)[0];
}

function readBE32(buffer: any) {
  if (buffer.length !== 4) throw new Error("Only 4byte buffers allowed!");

  if (getEndian() !== "big") buffer = buffer.reverse();

  return new Uint32Array(buffer.buffer)[0];
}

export function bufferToHex(buffer: ArrayBuffer) {
  // buffer is an ArrayBuffer
  return Array.prototype.map
    .call(new Uint8Array(buffer), (x) => ("00" + x.toString(16)).slice(-2))
    .join("");
}

// https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
export function parseAuthData(buffer: Uint8Array) {
  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  const flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  const flagsInt = flagsBuf[0];
  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt,
  };

  const counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  const counter = readBE32(counterBuf);

  let aaguid = undefined;
  let credID = undefined;
  let COSEPublicKey = undefined;

  if (flags.at) {
    aaguid = buffer.slice(0, 16);
    buffer = buffer.slice(16);
    const credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    const credIDLen = readBE16(credIDLenBuf);
    credID = buffer.slice(0, credIDLen);
    buffer = buffer.slice(credIDLen);
    COSEPublicKey = buffer;
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey,
  };
}

export function publicKeyCredentialToJSON(pubKeyCred: any): any {
  if (pubKeyCred instanceof Array) {
    const arr = [];
    for (const i of pubKeyCred) {
      arr.push(publicKeyCredentialToJSON(i));
    }

    return arr;
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return encode(pubKeyCred);
  }

  if (pubKeyCred instanceof Object) {
    const obj: { [key: string]: any } = {};

    for (const key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
    }

    return obj;
  }

  return pubKeyCred;
}

/*
var preformatMakeCredReq = (makeCredReq) => {
  makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
  makeCredReq.user.id = base64url.decode(makeCredReq.user.id);

  return makeCredReq;
};

var preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = base64url.decode(getAssert.challenge);

  if (getAssert.allowCredentials) {
    for (let allowCred of getAssert.allowCredentials) {
      allowCred.id = base64url.decode(allowCred.id);
    }
  }

  return getAssert;
};

*/
