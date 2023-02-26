<template>
  <div class="container">
    <div class="buttons">
      <div class="register" @click="register">Register</div>
      <div class="auth" @click="authenticate">Authenticate</div>
    </div>
    <div class="result">
      {{ result }}
    </div>
    <div class="error">{{ error }}</div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { randomBytes, sha256, concat, hexlify, toUtf8Bytes } from "ethers";
import { client } from "@passwordless-id/webauthn";
import { bufferToString, bufferToHex, parseAuthData } from "@/utils/helpers";
import { AsnParser } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'


const result = ref("");
const error = ref("");

function clearResult() {
  result.value = "";
}

function setResult(text: string) {
  result.value = result.value + ", " + text;
}

function toBuffer(txt: string): Uint8Array {
  return Uint8Array.from(txt, (c) => c.charCodeAt(0));
}

function parseBase64url(txt: string): Uint8Array {
  const base64 = txt.replace(/-/gi, "+").replace(/_/gi, "/") // base64url -> base64
  return toBuffer(atob(base64));
}


async function register() {
  clearResult();
  const challenge = sha256(randomBytes(32));
  const username = "loo@example.com";

  try {
    const credential = await client.register(username, challenge);
    setResult("Registered " + credential.credential.publicKey);
  } catch (err) {
    setResult("FAIL: " + (err as Error).message);
  }
}

async function authenticate() {
  clearResult();

  const challenge = randomBytes(32);
  const publicKey = { challenge };

  try {
    const credential = await navigator.credentials.get({
      publicKey,
    });

    if (!credential) {
      return;
    }
    setResult("SUCCESSFULLY GOT AN ASSERTION!");
  } catch (err) {
    error.value = (err as Error).message;
  }
}
</script>
<style scoped>
.container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100vh;
  gap: 20px;
}
.buttons {
  display: flex;
  flex-direction: row;
}
.buttons > div {
  border: 2px solid #ccc;
  border-radius: 10px;
  margin: 10px;
  padding: 20px;
  cursor: pointer;
  color: white;
  text-align: center;
  min-width: 100px;
}

.buttons > div:hover {
  opacity: 0.8;
  transform: scale(1.01);
}

.register {
  background-color: #1c315e;
}

.auth {
  background-color: #227c70;
}

.result {
  word-break: break-all;
  overflow-wrap: break-word;
  overflow: scroll;
  width: 100%;
}

.error {
  color: red;
}
</style>
