import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// DT-003 boundary guardrails (frozen delivery-transports plan, Phase 0).
// WHAT THIS ENFORCES:
//   1. Carrier vocabulary appears ONLY under the sanctioned adapter home
//      (src/delivery/ — does not exist yet; the allowlist is forward-dated so
//      Phase 1 needs no guardrail edit). The peer-link/e2ee/device-link
//      session surface stays carrier-blind, and no global email index can
//      grow anywhere in the SDK.
//   2. `RezClient.sendPayload` is FROZEN RezNet-only with no new callers:
//      it bypasses the mesh seam (raw mailbox.deposit) and the plan resolved
//      it as frozen-with-a-no-new-callers-test rather than routed. The only
//      permitted call sites are its own definition and the two pinned test
//      files.
//   3. The SDK never writes chat-owned KV prefixes (app:*, chat-server:*) —
//      prefix ownership is the only isolation on the shared store.
// WHAT IS DELIBERATELY NOT ENFORCED: docs and test prose; the `xfer:`/
// `file:` keys FileTransferService writes into a chat-INJECTED handle (a
// pre-existing, tracked convention breach — neither prefix is chat-owned,
// so it does not trip rule 3; DT-101 carries the tracking note).
// See rez-core/docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(__dirname, "..");
const SRC = path.join(SDK_ROOT, "src");

const CARRIER_PATTERN = /smtp|imap|nodemailer|mailparser|\bpop3\b|(^|[^a-z])e-?mail/i;
const CARRIER_ALLOWED_DIRS = ["src/delivery/"];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && full.endsWith(".js")) out.push(full);
  }
  return out;
}

function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

test("carrier vocabulary exists only under src/delivery/ (the RDeliveryTransport home)", () => {
  const violations = [];
  for (const file of walk(SRC)) {
    const rel = path.relative(SDK_ROOT, file);
    if (CARRIER_ALLOWED_DIRS.some((d) => rel.startsWith(d))) continue;
    const lines = fs.readFileSync(file, "utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (CARRIER_PATTERN.test(lines[i])) {
        violations.push(rel + ":" + (i + 1) + "  " + lines[i].trim());
      }
    }
  }
  assert.deepEqual(violations, [],
    "Carrier vocabulary outside src/delivery/. Carriers are RDeliveryTransport "
    + "adapters; the rest of the SDK (peer-link, e2ee, device-link, client) stays "
    + "carrier-blind, and no email-address index may exist anywhere. "
    + "See rez-core/docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md.\n" + violations.join("\n"));
});

test("sendPayload is frozen: no production caller may use the raw-deposit bypass", () => {
  const violations = [];
  for (const file of walk(SRC)) {
    const rel = path.relative(SDK_ROOT, file);
    const stripped = stripComments(fs.readFileSync(file, "utf8"));
    const lines = stripped.split("\n");
    for (let i = 0; i < lines.length; i++) {
      // A CALL (`x.sendPayload(`) is a violation; the definition
      // (`async sendPayload(`) in RezClient.js is not.
      if (/\.\s*sendPayload\s*\(/.test(lines[i])) {
        violations.push(rel + ":" + (i + 1) + "  " + lines[i].trim());
      }
    }
  }
  assert.deepEqual(violations, [],
    "New sendPayload caller detected. sendPayload bypasses the mesh seam "
    + "(raw mailbox.deposit, no delivery planning, no carrier boundary) and is "
    + "frozen RezNet-only per the delivery-transports plan (DT-003). Route new "
    + "sends through mesh.dispatch / the delivery layer instead.\n" + violations.join("\n"));
});

// GRANDFATHERED breaches — pre-existing keys already on disk for real users;
// renaming a live prefix needs a data migration, which is not a guardrail's
// call. TRACKED as DT-101 items alongside the xfer:/file: FileTransferService
// breach. Nothing may be ADDED here without that migration plan.
const GRANDFATHERED_CHAT_PREFIX_LINES = new Set([
  'src/peer-link/PeerLinkService.js|const PEER_LINK_INVITE_PREFIX = "app:peer-links:invites/";',
  'src/peer-link/PeerLinkService.js|const PEER_LINK_INVITE_HASH_PREFIX = "app:peer-links:inviteHash/";',
]);

test("the SDK never writes chat-owned KV prefixes (app:*, chat-server:*)", () => {
  const violations = [];
  for (const file of walk(SRC)) {
    const rel = path.relative(SDK_ROOT, file);
    const stripped = stripComments(fs.readFileSync(file, "utf8"));
    const lines = stripped.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (/["'`](app:|chat-server:)/.test(lines[i])) {
        if (GRANDFATHERED_CHAT_PREFIX_LINES.has(rel + "|" + lines[i].trim())) continue;
        violations.push(rel + ":" + (i + 1) + "  " + lines[i].trim());
      }
    }
  }
  assert.deepEqual(violations, [],
    "SDK code referenced a chat-owned KV prefix. The shared store is isolated by "
    + "prefix ownership ONLY (SDK: peer-link:*/sdk:*; chat: app:*/chat-server:*): "
    + "a cross-write here is chat storage corruption waiting to happen.\n"
    + violations.join("\n"));
});

// ADR naming rule (ADR-DELIVERY-TRANSPORT-LAYERS §2): the carrier directory
// is EXEMPT from the vocabulary ban above (an SMTP adapter legitimately says
// "smtp") but NOT from naming. Abstract interface: RDeliveryTransport.
// Implementations: <Carrier>DeliveryTransport. Prohibited: bare `Transport`
// and any carrier name ending in `Transport` that omits `Delivery`.
function violatesCarrierNaming(name) {
  if (!/Transport$/.test(name)) return false; // rule governs *Transport names only
  if (name === "RDeliveryTransport") return false; // the abstract interface
  return !/DeliveryTransport$/.test(name); // implementations must carry "Delivery"
}

// The rule above is name-shaped and therefore blind to a carrier that avoids
// the word entirely (`class SmtpCarrier extends RDeliveryTransport {}`). EVERY
// implementation — identified by what it extends, not by what it is called —
// must be `<Carrier>DeliveryTransport`, and so must its file.
function violatesImplementationNaming(name) {
  return !/^[A-Za-z0-9_$]+DeliveryTransport$/.test(name);
}

test("carrier naming rule: positive fixtures pin the ADR contract", () => {
  // Allowed — the frozen plan's own names must pass.
  for (const ok of ["RDeliveryTransport", "RezNetDeliveryTransport", "FakeDeliveryTransport", "SmtpDeliveryTransport", "DeliveryRouter"]) {
    assert.equal(violatesCarrierNaming(ok), false, ok + " must be permitted");
  }
  // Prohibited — ambiguous names that collide with the non-carrier layers.
  for (const bad of ["Transport", "SmtpTransport", "EmailTransport", "ImapTransport"]) {
    assert.equal(violatesCarrierNaming(bad), true, bad + " must be rejected");
  }
  // Implementation rule: an RDeliveryTransport subclass must END in
  // DeliveryTransport regardless of how it dodges the *Transport suffix.
  for (const ok of ["RezNetDeliveryTransport", "FakeDeliveryTransport", "SmtpDeliveryTransport"]) {
    assert.equal(violatesImplementationNaming(ok), false, ok + " must be permitted as an implementation");
  }
  for (const bad of ["SmtpCarrier", "EmailAdapter", "SmtpTransport", "DeliveryTransport"]) {
    assert.equal(violatesImplementationNaming(bad), true, bad + " must be rejected as an implementation name");
  }
  // The exact fixture from the Phase 0 audit: the class-name rule alone lets
  // this through, so the extends-based rule is the one that must catch it.
  const FIXTURE = "class SmtpCarrier extends RDeliveryTransport {}";
  const found = [...FIXTURE.matchAll(IMPLEMENTS_RE)].map((m) => m[1]);
  assert.deepEqual(found, ["SmtpCarrier"], "the extends scanner sees the fixture");
  assert.equal(violatesCarrierNaming("SmtpCarrier"), false, "the name-shaped rule alone does NOT catch it");
  assert.equal(violatesImplementationNaming(found[0]), true, "the implementation rule catches it");
});

// `class X extends RDeliveryTransport` — the authoritative marker of a carrier
// implementation. Kept module-level so the fixture test and the scan below use
// exactly the same matcher (a divergence here would be a silent hole).
const IMPLEMENTS_RE = /\bclass\s+([A-Za-z0-9_$]+)\s+extends\s+RDeliveryTransport\b/g;

test("carrier naming rule: every RDeliveryTransport implementation is named <Carrier>DeliveryTransport", () => {
  const deliveryDir = path.join(SRC, "delivery");
  const violations = [];
  // Implementations may live anywhere in the SDK, not only under src/delivery/
  // — scan the whole tree so a carrier cannot escape the rule by relocating.
  for (const file of walk(SRC)) {
    const rel = path.relative(SDK_ROOT, file);
    const stripped = stripComments(fs.readFileSync(file, "utf8"));
    IMPLEMENTS_RE.lastIndex = 0;
    let m;
    while ((m = IMPLEMENTS_RE.exec(stripped)) !== null) {
      const className = m[1];
      if (violatesImplementationNaming(className)) {
        violations.push(rel + "  class " + className + " extends RDeliveryTransport");
      }
      const base = path.basename(file, ".js");
      if (violatesImplementationNaming(base)) {
        violations.push(rel + "  (file holding an RDeliveryTransport implementation)");
      }
    }
  }
  assert.ok(deliveryDir.endsWith(path.join("src", "delivery")), "delivery home path is pinned");
  assert.deepEqual(violations, [],
    "An RDeliveryTransport implementation is not named <Carrier>DeliveryTransport. "
    + "The rule is about what a class EXTENDS, not what it happens to be called: "
    + "`class SmtpCarrier extends RDeliveryTransport {}` is prohibited exactly like "
    + "`SmtpTransport`. The containing file must carry the same name. "
    + "See rez-core/docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md §2.\n"
    + violations.join("\n"));
});

test("carrier naming rule: every class and file under src/delivery/ complies", () => {
  const deliveryDir = path.join(SRC, "delivery");
  const violations = [];
  for (const file of walk(deliveryDir)) {
    const rel = path.relative(SDK_ROOT, file);
    const base = path.basename(file, ".js");
    if (violatesCarrierNaming(base)) {
      violations.push(rel + "  (file name)");
    }
    const stripped = stripComments(fs.readFileSync(file, "utf8"));
    const classRe = /\bclass\s+([A-Za-z0-9_$]+)/g;
    let m;
    while ((m = classRe.exec(stripped)) !== null) {
      if (violatesCarrierNaming(m[1])) {
        violations.push(rel + "  class " + m[1]);
      }
    }
  }
  assert.deepEqual(violations, [],
    "Carrier naming violation. Implementations are <Carrier>DeliveryTransport "
    + "(RezNetDeliveryTransport, FakeDeliveryTransport, ...); bare `Transport` "
    + "and *Transport names omitting `Delivery` are prohibited — they collide "
    + "with the SDK-connection and hop layers. "
    + "See rez-core/docs/adr/ADR-DELIVERY-TRANSPORT-LAYERS.md §2.\n"
    + violations.join("\n"));
});
