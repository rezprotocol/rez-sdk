import test from "node:test";
import assert from "node:assert/strict";

import {
  deriveBrowserAccountRecovery,
  generateBrowserMnemonic,
  openBrowserRecoveryMnemonic,
  sealBrowserRecoveryMnemonic,
  validateBrowserMnemonic,
} from "../src/keystore/BrowserRecovery.js";

test("browser recovery phrase deterministically derives account and account-DH identities", async () => {
  const mnemonic = await generateBrowserMnemonic({ words: 24 });
  assert.equal(mnemonic.split(" ").length, 24);
  assert.equal(await validateBrowserMnemonic(mnemonic), true);

  const first = await deriveBrowserAccountRecovery(mnemonic);
  const second = await deriveBrowserAccountRecovery(mnemonic);
  assert.equal(first.identity.getAccountId(), second.identity.getAccountId());
  assert.deepEqual(first.identityKeyPair, second.identityKeyPair);
  assert.deepEqual(first.accountIdentityDhKeyPair, second.accountIdentityDhKeyPair);
});

test("browser recovery phrase is encrypted under the account password", async () => {
  const mnemonic = await generateBrowserMnemonic({ words: 12 });
  const envelope = await sealBrowserRecoveryMnemonic({ mnemonic, password: "correct horse battery staple" });

  assert.equal(await openBrowserRecoveryMnemonic({ envelope, password: "correct horse battery staple" }), mnemonic);
  await assert.rejects(
    () => openBrowserRecoveryMnemonic({ envelope, password: "wrong password" }),
    /decrypt|operation|authentication/i,
  );
});
