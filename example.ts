import {
  aesGcmDecrypt,
  aesGcmEncrypt,
} from "https://deno.land/x/aes_gcm@v1.0.2/mod.ts";

const input = "secret text";

const password = "any strong password ^%&!$0P";

const ctxt = await aesGcmEncrypt(input, password);

const output = await aesGcmDecrypt(ctxt, password);

console.log(input === output);
