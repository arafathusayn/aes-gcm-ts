import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.149.0/testing/asserts.ts";

import { aesGcmDecrypt, aesGcmEncrypt } from "./aes-gcm.ts";

Deno.test(
  "encryption and decryption work for any text string and any password string",
  async () => {
    const input = new Array(Math.ceil(Math.random() * 10000 + 100))
      .fill(Math.random())
      .join(" ");

    const password = new TextDecoder().decode(
      crypto.getRandomValues(
        new Uint8Array(Math.ceil(Math.random() * 100 + 10))
      )
    );

    const ctxt = await aesGcmEncrypt(input, password);

    const output = await aesGcmDecrypt(ctxt, password);

    assertEquals(input, output);
  }
);

Deno.test("decryption should fail for different password", async () => {
  const input = new Array(Math.ceil(Math.random() * 10000 + 100))
    .fill(Math.random())
    .join(" ");

  const password = new TextDecoder().decode(
    crypto.getRandomValues(new Uint8Array(Math.ceil(Math.random() * 100 + 10)))
  );

  const ctxt = await aesGcmEncrypt(input, password);

  await assertRejects(() => aesGcmDecrypt(ctxt, password + Math.random()));
});

Deno.test("throws for invalid parameters", async () => {
  // @ts-expect-error Expected 2 arguments, but got 0.
  await assertRejects(() => aesGcmEncrypt());

  // @ts-expect-error Expected 2 arguments, but got 0.
  await assertRejects(() => aesGcmDecrypt());

  await assertRejects(() => aesGcmEncrypt("", ""));

  await assertRejects(() => aesGcmDecrypt("", ""));

  // @ts-expect-error Expected 2 arguments, but got 1.
  await assertRejects(() => aesGcmEncrypt(""));

  // @ts-expect-error Expected 2 arguments, but got 1.
  await assertRejects(() => aesGcmDecrypt(""));

  // @ts-expect-error Argument of type 'undefined' is not assignable to parameter of type 'string'.
  await assertRejects(() => aesGcmEncrypt(undefined, ""));

  // @ts-expect-error Argument of type 'undefined' is not assignable to parameter of type 'string'.
  await assertRejects(() => aesGcmDecrypt(undefined, ""));

  // test invalid regex match for wrong ciphertext
  await assertRejects(
    () => aesGcmDecrypt("wrong", "_"),
    "Invalid regex match for ciphertext in aesGcmDecrypt function"
  );

  // test invalid iv
  await assertRejects(
    () => aesGcmDecrypt("_", "_"),
    "Invalid iv in ciphertext for aesGcmDecrypt function"
  );
});
