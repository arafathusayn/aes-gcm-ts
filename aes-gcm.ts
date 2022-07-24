/**
 * @example
 * const ciphertext = await aesGcmEncrypt('my secret text', 'strong password here')
 */
export const aesGcmEncrypt = async (plaintext: string, password: string) => {
  if (!plaintext || !password) {
    throw new Error("Invalid parameters to aesGcmEncrypt function");
  }

  const pwUtf8 = new TextEncoder().encode(password); // encode password as UTF-8

  // AES key data must be 128 or 256 bits
  const pwHash = await crypto.subtle.digest("SHA-256", pwUtf8); // hash the password

  // iv length must be equal to 12 or 16 bytes
  const iv = crypto.getRandomValues(new Uint8Array(16)); // get 128-bit random iv

  const alg = { name: "AES-GCM", iv: iv }; // specify algorithm to use

  const key = await crypto.subtle.importKey("raw", pwHash, alg, false, [
    "encrypt",
  ]); // generate key from pw

  const ptUint8 = new TextEncoder().encode(plaintext); // encode plaintext as UTF-8
  const ctBuffer = await crypto.subtle.encrypt(alg, key, ptUint8); // encrypt plaintext using key

  const ctArray = Array.from(new Uint8Array(ctBuffer)); // ciphertext as byte array
  const ctStr = ctArray.map((byte) => String.fromCharCode(byte)).join(""); // ciphertext as string
  const ctBase64 = btoa(ctStr); // encode ciphertext as base64

  const ivHex = Array.from(iv)
    .map((b) => ("00" + b.toString(16)).slice(-2))
    .join(""); // iv as hex string

  return ivHex + ctBase64; // return iv+ciphertext
};

/**
 * @example
 * const plaintext = await aesGcmDecrypt(ciphertext, 'password here')
 */
export const aesGcmDecrypt = async (ciphertext: string, password: string) => {
  if (!ciphertext || !password) {
    throw new Error("Invalid parameters to aesGcmDecrypt function");
  }

  const pwUtf8 = new TextEncoder().encode(password); // encode password as UTF-8
  const pwHash = await crypto.subtle.digest("SHA-256", pwUtf8); // hash the password

  const iv = ciphertext
    .slice(0, 32)
    .match(/.{2}/g)
    ?.map((byte) => parseInt(byte, 16)); // get iv from ciphertext

  if (!iv) {
    throw new Error("Invalid iv in ciphertext for aesGcmDecrypt function");
  }

  const alg = { name: "AES-GCM", iv: new Uint8Array(iv) }; // specify algorithm to use

  const key = await crypto.subtle.importKey("raw", pwHash, alg, false, [
    "decrypt",
  ]); // use pw to generate key

  const ctStr = atob(ciphertext.slice(32)); // decode base64 ciphertext

  const match = ctStr.match(/[\s\S]/g);

  if (!match) {
    throw new Error(
      "Invalid regex match for ciphertext in aesGcmDecrypt function"
    );
  }

  const ctUint8 = new Uint8Array(match.map((ch) => ch.charCodeAt(0))); // ciphertext as Uint8Array

  const plainBuffer = await crypto.subtle.decrypt(alg, key, ctUint8); // decrypt ciphertext using key

  const plaintext = new TextDecoder().decode(plainBuffer); // decode password from UTF-8

  return plaintext; // return the plaintext
};
