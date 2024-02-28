import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = arrayBufferToBase64(exportedKeyBuffer);
  return exportedKeyBase64;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (key === null) {
    return null;
  }
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = arrayBufferToBase64(exportedKeyBuffer);
  return exportedKeyBase64;
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "spki",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const dataBuffer = base64ToArrayBuffer(b64Data);
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    dataBuffer
  );
  const encryptedDataBuffer = new Uint8Array(encryptedData);
  const encryptedDataBase64 = arrayBufferToBase64(encryptedDataBuffer);
  return encryptedDataBase64;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  const encryptedDataBuffer = base64ToArrayBuffer(data);
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedDataBuffer
  );
  const decryptedDataBuffer = new Uint8Array(decryptedData);
  const decryptedDataBase64 = arrayBufferToBase64(decryptedDataBuffer);
  return decryptedDataBase64;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // Ensure the use of AES-CBC for the algorithm
  const key = await crypto.subtle.generateKey(
    { name: "AES-CBC", length: 256 }, // Use AES-CBC with a 256-bit key
    true, // The key is extractable
    ["encrypt", "decrypt"] // The key can be used for encryption and decryption
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  const exportedKeyBuffer = new Uint8Array(exportedKey);
  const exportedKeyBase64 = arrayBufferToBase64(exportedKeyBuffer);
  return exportedKeyBase64;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "raw",
    keyBuffer,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );
  return importedKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: crypto.getRandomValues(new Uint8Array(12)),
    },
    key,
    encodedData
  );

  const encryptedDataBuffer = new Uint8Array(encryptedData);
  const encryptedDataBase64 = arrayBufferToBase64(encryptedDataBuffer);

  return encryptedDataBase64;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);

  const encryptedDataBuffer = base64ToArrayBuffer(encryptedData);

  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(12),
    },
    key,
    encryptedDataBuffer
  );

  const decoder = new TextDecoder();
  const decryptedDataString = decoder.decode(decryptedData);

  return decryptedDataString;
}
