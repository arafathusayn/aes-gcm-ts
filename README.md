Modern Web Browser and Deno compatible AES-GCM library written in TypeScript

Deno Import:
```js
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
} from "https://deno.land/x/aes_gcm@v1.0.2/mod.ts";
```

Example:
```js
const input = "secret text";

const password = "any strong password ^%&!$0P";

const ctxt = await aesGcmEncrypt(input, password);

const output = await aesGcmDecrypt(ctxt, password);

console.log(input === output);
```

[Documentation](https://doc.deno.land/https://deno.land/x/aes_gcm/mod.ts)