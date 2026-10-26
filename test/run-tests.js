import assert from "node:assert/strict";
import * as L from "../src/messagePopup/lib.js";
import { joinTxt, createDns } from "../src/messagePopup/dns.js";
import { authenticHeaders, forgedARHeaders, v6Headers, v6NoArHeaders, m365Headers, gmailHeaders, internalHeaders, forgedInternalExternalHop, forgedInternalForeignAR, outboundM365Ipv4, outboundM365Ipv6, spoofHeaders, mockDns, zone } from "./fixtures.js";

let pass = 0, fail = 0;
async function test(name, fn) {
    try { await fn(); pass++; console.log("  ok  " + name); }
    catch (e) { fail++; console.log("  FAIL " + name + "\n       " + e.message); }
}

await test("parseAddress with display name", () => {
    assert.deepEqual(L.parseAddress('"Example Billing" <Billing@Example.com>'), { name: "Example Billing", address: "Billing@Example.com", domain: "example.com" });
    assert.equal(L.parseAddress("<>").address, "");
    assert.equal(L.parseAddress("plain@x.example").domain, "x.example");
});
await test("parseReceived postfix", () => {
    const r = L.parseReceived(authenticHeaders.received[0]);
    assert.equal(r.helo, "out-3.mail.example.com"); assert.equal(r.rdns, "out-3.mail.example.com");
    assert.equal(r.ip, "203.0.113.25"); assert.equal(r.by, "mx.home.example.net");
    assert.match(r.date, /^Wed, 14 Oct 2026 18:02:11/);
});
await test("parseReceived postfix unknown rdns", () => {
    const r = L.parseReceived(spoofHeaders.received[1]);
    assert.equal(r.helo, "mailer.example.org"); assert.equal(r.rdns, ""); assert.equal(r.ip, "198.51.100.77");
});
await test("parseReceived exim with helo=", () => {
    const r = L.parseReceived("from smtp.rdns.example ([203.0.113.7] helo=claimed.example) by mx.example with esmtps; Mon, 1 Jan 2026 00:00:00 +0000");
    assert.equal(r.helo, "claimed.example"); assert.equal(r.rdns, "smtp.rdns.example"); assert.equal(r.ip, "203.0.113.7");
});
await test("parseReceived IPv6 in brackets", () => {
    const r = L.parseReceived("from mail.example.com (mail.example.com [IPv6:2001:db8::25]) by mx.example.net; Mon, 1 Jan 2026 00:00:00 +0000");
    assert.equal(r.ip, "2001:db8::25");
});
await test("parseReceived Microsoft style ip in parens", () => {
    const r = L.parseReceived("from EX1.contoso.example (2001:db8:1::5) by EX2.contoso.example (2001:db8:1::6) with Microsoft SMTP Server; Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8:1::5"); assert.equal(r.by, "ex2.contoso.example");
});
await test("findHandoff skips loopback hop", () => {
    const h = L.findHandoff(spoofHeaders.received.map(L.parseReceived));
    assert.equal(h.index, 1); assert.equal(h.hop.ip, "198.51.100.77");
});
await test("DKIM-Signature d= and s=", () => {
    assert.deepEqual(L.parseDkimSignature(authenticHeaders["dkim-signature"][0]), { d: "example.com", s: "s1" });
});
await test("parseAuthResults", () => {
    const a = L.parseAuthResults(authenticHeaders["authentication-results"][0]);
    assert.equal(a.authserv, "mx.home.example.net");
    assert.deepEqual(a.results.map(r => r.method + "=" + r.result), ["spf=pass", "dkim=pass", "dmarc=pass"]);
    assert.equal(a.results[0].props["smtp.mailfrom"], "bounce-8812@mail.example.com");
    assert.equal(a.results[2].cprops.p, "reject");
});
await test("selectAR trusts topmost / matching authserv only", () => {
    const list = authenticHeaders["authentication-results"].map(L.parseAuthResults);
    const s = L.selectAR(list, "mx.home.example.net");
    assert.equal(s.trusted.length, 1); assert.equal(s.flagged.length, 1); assert.equal(s.flagged[0].authserv, "evil.example.org");
    const s2 = L.selectAR([list[1], list[0]], "mx.home.example.net");
    assert.equal(s2.trusted.length, 2);
});
await test("CIDR v4/v6, ptrName", () => {
    assert.ok(L.cidrMatch("203.0.113.25", "203.0.113.0", 26));
    assert.ok(!L.cidrMatch("203.0.113.70", "203.0.113.0", 26));
    assert.ok(L.cidrMatch("2001:db8:10::1", "2001:db8:10::", 48));
    assert.ok(!L.cidrMatch("2001:db8:11::1", "2001:db8:10::", 48));
    assert.ok(L.sameIP("::ffff:192.0.2.1", "0:0:0:0:0:ffff:c000:201"));
    assert.equal(L.ptrName("2001:db8::1").slice(0, 8), "1.0.0.0.");
    assert.ok(!L.isPublicIP("10.1.2.3") && L.isPublicIP("8.8.8.8") && !L.isPublicIP("fe80::1"));
});
await test("joinTxt", () => {
    assert.equal(joinTxt('"v=spf1 ip4:1.2.3.4 " "-all"'), "v=spf1 ip4:1.2.3.4 -all");
    assert.equal(joinTxt("v=spf1 -all"), "v=spf1 -all");
});
const dns = mockDns();
await test("SPF ip4 pass via redirect", async () => {
    assert.equal((await L.checkSpf("203.0.113.25", "mail.example.com", dns)).result, "pass");
});
await test("SPF include ip6 / a / mx pass", async () => {
    assert.equal((await L.checkSpf("2001:db8:10::9", "example.com", dns)).result, "pass");
    assert.equal((await L.checkSpf("198.51.100.5", "example.com", dns)).result, "pass");
    assert.equal((await L.checkSpf("198.51.100.9", "example.com", dns)).result, "pass");
});
await test("SPF -all fail, none, softfail", async () => {
    assert.equal((await L.checkSpf("198.51.100.77", "example.com", dns)).result, "fail");
    assert.equal((await L.checkSpf("198.51.100.77", "nospf.example", dns)).result, "none");
    const d2 = mockDns({ "TXT soft.example": ["v=spf1 ~all"] });
    assert.equal((await L.checkSpf("1.2.3.4", "soft.example", d2)).result, "softfail");
});
await test("SPF lookup limit / loop → permerror", async () => {
    assert.equal((await L.checkSpf("1.2.3.4", "loop1.example", dns)).result, "permerror");
    const z = {}; for (let i = 0; i < 12; i++) z["TXT d" + i + ".example"] = [`v=spf1 a:x${i}.example include:d${i + 1}.example -all`];
    z["TXT d12.example"] = ["v=spf1 +all"];
    const r = await L.checkSpf("1.2.3.4", "d0.example", mockDns(z));
    assert.equal(r.result, "permerror"); assert.match(r.reason, /too many/);
});
await test("SPF multiple records → permerror; DNS error → temperror", async () => {
    assert.equal((await L.checkSpf("1.2.3.4", "m.example", mockDns({ "TXT m.example": ["v=spf1 -all", "v=spf1 +all"] }))).result, "permerror");
    const bad = { ...dns, txt: async () => { throw new Error("x"); } };
    assert.equal((await L.checkSpf("1.2.3.4", "e.example", bad)).result, "temperror");
});
await test("orgDomain / alignment", () => {
    assert.equal(L.orgDomain("a.b.example.com"), "example.com");
    assert.equal(L.orgDomain("mail.shop.co.uk"), "shop.co.uk");
    assert.ok(L.aligned("mail.example.com", "example.com"));
    assert.ok(!L.aligned("mail.example.com", "example.com", "s"));
});
await test("analyze: trusted AR + forged AR present", async () => {
    const r = await L.analyze(authenticHeaders, dns);
    assert.equal(r.confirm.spf.source.type, "ar"); assert.equal(r.confirm.spf.domain, "mail.example.com");
    assert.equal(r.confirm.dmarc.policy, "reject"); assert.equal(r.confirm.arFlagged.length, 1);
    assert.equal(r.confirm.rdns.result, "neutral"); // PTR smtp25 != HELO out-3, forward-confirmed
    assert.equal(r.verdict.level, "suspicious"); assert.equal(r.verdict.key, "reasonDockedAR");
    assert.equal(r.claim.handoff.hop.helo, "out-3.mail.example.com");
});
await test("analyze: no AR fallback → spoofed", async () => {
    const r = await L.analyze(spoofHeaders, dns);
    assert.equal(r.confirm.spf.source.type, "own"); assert.equal(r.confirm.spf.result, "fail");
    assert.equal(r.confirm.dkim.result, "none"); assert.equal(r.confirm.dmarc.result, "fail");
    assert.equal(r.confirm.rdns.result, "fail"); assert.equal(r.verdict.level, "spoofed");
});
await test("analyze: no AR, unverified aligned DKIM → DMARC neutral, suspicious (not spoofed)", async () => {
    const h = { ...spoofHeaders, "dkim-signature": ["v=1; d=example.com; s=s1; b=x"] };
    const r = await L.analyze(h, dns);
    assert.equal(r.confirm.dkim.result, "neutral"); assert.equal(r.confirm.dmarc.result, "neutral");
    assert.equal(r.verdict.level, "suspicious"); assert.equal(r.verdict.key, "reasonSpfFailDkimUnverified"); // SPF fail, aligned DKIM present but unverifiable
});
await test("analyze: own SPF pass aligned → authentic", async () => {
    const h = { ...spoofHeaders, received: ["from out-3.mail.example.com (smtp25.example.com [203.0.113.25]) by mx.home.example.net; Wed, 14 Oct 2026"] };
    const r = await L.analyze(h, dns);
    assert.equal(r.confirm.spf.result, "pass"); assert.equal(r.confirm.dmarc.result, "pass");
    assert.equal(r.verdict.level, "authentic");
});
await test("analyze: clean trusted AR → authentic", async () => {
    const h = { ...authenticHeaders, "authentication-results": [authenticHeaders["authentication-results"][0]] };
    const r = await L.analyze(h, dns);
    assert.equal(r.verdict.level, "authentic"); assert.equal(r.confirm.arFlagged.length, 0);
});
await test("AR flagging: same-org internal AR not flagged, forged one flagged, verdict docked", async () => {
    const r = await L.analyze(forgedARHeaders, dns);
    assert.deepEqual(r.confirm.arFlagged.map(a => a.authserv), ["evil.example.org"]);
    assert.equal(r.confirm.arIgnored, 1); // relay2.home.example.net: same org as mx.home.example.net
    assert.equal(r.verdict.level, "suspicious");
});
await test("verdict docking: suspicious stays suspicious with AR reason; spoofed unchanged", () => {
    const base = { dmarc: { result: "none" }, dkim: { items: [] }, spf: { result: "neutral" }, arFlagged: [{}] };
    const v = L.verdict("example.com", base);
    assert.equal(v.level, "suspicious"); assert.equal(v.key, "reasonMixedAR");
    assert.equal(L.verdict("example.com", { ...base, dmarc: { result: "fail" } }).level, "spoofed");
    assert.equal(L.verdict("example.com", { ...base, arFlagged: [] }).key, "reasonMixed");
});
await test("analyze: own-check resolver names are reported", async () => {
    const f = async () => ({ ok: true, json: async () => ({ Status: 0, Answer: [] }) });
    const r = await L.analyze(spoofHeaders, createDns(f, [{ name: "R1", url: "https://r1.example/q" }]));
    assert.deepEqual(r.confirm.spf.source.resolvers, ["R1"]); assert.deepEqual(r.confirm.rdns.source.resolvers, ["R1"]);
});

// ---- resolver fallback ----
const OK = answer => ({ ok: true, json: async () => ({ Status: 0, Answer: answer }) });
const RS = [{ name: "A", url: "https://a.example/q" }, { name: "B", url: "https://b.example/q" }, { name: "C", url: "https://c.example/q" }];
const host = u => new URL(u).hostname[0].toUpperCase();
await test("fallback: network error → next resolver, order respected", async () => {
    const calls = [];
    const f = async u => { calls.push(host(u)); if (host(u) === "A") throw new TypeError("network"); return OK([{ type: 1, data: "192.0.2.1" }]); };
    const d = createDns(f, RS); assert.deepEqual(await d.a("x.example"), ["192.0.2.1"]);
    assert.deepEqual(calls, ["A", "B"]); assert.deepEqual([...d.used], ["B"]);
});
await test("fallback: HTTP error and SERVFAIL → next resolver", async () => {
    const f = async u => host(u) === "A" ? { ok: false, status: 503 } : host(u) === "B" ? { ok: true, json: async () => ({ Status: 2 }) } : OK([{ type: 1, data: "192.0.2.3" }]);
    const d = createDns(f, RS); assert.deepEqual(await d.a("x.example"), ["192.0.2.3"]); assert.deepEqual([...d.used], ["C"]);
});
await test("fallback: timeout → next resolver", async () => {
    const f = (u, o) => host(u) === "A" ? new Promise(() => {}) : Promise.resolve(OK([{ type: 1, data: "192.0.2.4" }]));
    const t0 = Date.now(); const d = createDns(f, RS, 100);
    assert.deepEqual(await d.a("x.example"), ["192.0.2.4"]); assert.ok(Date.now() - t0 < 1000);
});
await test("no fallback on NXDOMAIN", async () => {
    const calls = [];
    const f = async u => { calls.push(host(u)); return { ok: true, json: async () => ({ Status: 3 }) }; };
    assert.deepEqual(await createDns(f, RS).a("nx.example"), []); assert.deepEqual(calls, ["A"]);
});
await test("all resolvers failing → error", async () => {
    await assert.rejects(createDns(async () => { throw new Error("down"); }, RS).a("x.example"), /All resolvers failed/);
});
await test("shipped resolver list matches manifest host permissions exactly", async () => {
    const { RESOLVERS } = await import("../src/messagePopup/dns.js");
    const { readFileSync } = await import("node:fs");
    const m = JSON.parse(readFileSync(new URL("../src/manifest.json", import.meta.url)));
    const hosts = m.permissions.filter(p => p.startsWith("https://")).sort();
    assert.deepEqual(hosts, RESOLVERS.map(r => new URL(r.url).origin + "/*").sort());
    assert.equal(RESOLVERS[0].name, "Cloudflare"); assert.equal(RESOLVERS.at(-1).name, "Google");
});

await test("createDns parses Google JSON and Cloudflare header", async () => {
    let seen;
    const fake = async (url, opts) => { seen = { url, opts }; return { ok: true, json: async () => ({ Status: 0, Answer: [{ type: 5, data: "x." }, { type: 16, data: '"v=spf1 " "-all"' }] }) }; };
    assert.deepEqual(await createDns(fake).txt("a.example"), ["v=spf1 -all"]);
    assert.match(seen.url, /^https:\/\/cloudflare-dns\.com\/dns-query\?name=a\.example&type=TXT$/);
    assert.equal(seen.opts.headers.accept, "application/dns-json");
    const nx = async () => ({ ok: true, json: async () => ({ Status: 3 }) });
    assert.deepEqual(await createDns(nx).a("c.example"), []);
});


// ================= IPv6 =================
const dnsV6 = mockDns();
await test("v6: parsing compressed/uncompressed/mapped/zone/brackets", () => {
    const big = a => L.ipToBig(a).n;
    assert.equal(big("2001:db8::1"), big("2001:0db8:0000:0000:0000:0000:0000:0001"));
    assert.equal(big("2001:DB8::1"), big("2001:db8:0:0:0:0:0:1"));
    assert.equal(big("[2001:db8::1]"), big("2001:db8::1")); assert.equal(big("IPv6:2001:db8::1"), big("2001:db8::1"));
    assert.equal(big("fe80::1%eth0"), big("fe80::1"));
    assert.equal(big("::"), 0n); assert.equal(big("::1"), 1n); assert.equal(big("1::"), 1n << 112n);
    assert.equal(L.isIPv6("1:2:3:4:5:6:7:8:9"), false); assert.equal(L.isIPv6("1::2::3"), false); assert.equal(L.isIPv6("12345::1"), false);
    assert.equal(L.isIPv6("::ffff:300.1.1.1"), false);
});
await test("v6: IPv4-mapped normalizes to IPv4 and matches ip4 ranges", () => {
    assert.equal(L.normalizeIP("::ffff:192.0.2.9"), "192.0.2.9"); assert.equal(L.normalizeIP("::FFFF:c000:209"), "192.0.2.9");
    assert.equal(L.normalizeIP("[IPv6:2001:db8::1]"), "2001:db8::1");
    assert.ok(L.cidrMatch("::ffff:192.0.2.9", "192.0.2.0", 24)); assert.ok(L.sameIP("::ffff:192.0.2.9", "192.0.2.9"));
    assert.ok(!L.cidrMatch("::ffff:192.0.2.9", "2001:db8::", 32));
});
await test("v6: ip6 ranges (compressed/uncompressed, boundaries, /0, /128)", () => {
    assert.ok(L.cidrMatch("2001:db8:ffff::1", "2001:db8::", 32) === true);
    assert.ok(!L.cidrMatch("2001:db9::1", "2001:db8::", 32));
    assert.ok(L.cidrMatch("2001:db8::1", "2001:DB8:0:0:0:0:0:0", 32));
    assert.ok(L.cidrMatch("2001:db8::1", "2001:db8::1", 128) && !L.cidrMatch("2001:db8::2", "2001:db8::1", 128));
    assert.ok(L.cidrMatch("2001:db8::1", "::", 0)); assert.ok(!L.cidrMatch("2001:db8::1", "192.0.2.1", 24));
});
await test("v6: PTR nibble format", () => {
    assert.equal(L.ptrName("2001:db8::567:89ab"), "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    assert.equal(L.ptrName("2001:db8:25::5"), "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    assert.equal(L.ptrName("::1").split(".").length, 34); assert.equal(L.ptrName("192.0.2.1"), "1.2.0.192.in-addr.arpa");
});
await test("v6: isPublicIP skips ::1, fe80::/10, fc00::/7, ::, ff00::/8, mapped-private", () => {
    for (const a of ["::1", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1", "::", "ff02::1", "::ffff:10.1.2.3", "::ffff:192.168.0.1", "::ffff:127.0.0.1"])
        assert.equal(L.isPublicIP(a), false, a);
    for (const a of ["2001:db8::1", "2a00:1450::1", "::ffff:8.8.8.8", "fec0::1"]) assert.equal(L.isPublicIP(a), true, a);
});
await test("v6: findHandoff skips ::1 / fe80 / ULA / mapped-private hops", () => {
    const mk = ip => L.parseReceived(`from a.example (a.example [${ip}]) by b.example; Mon, 1 Jan 2026 00:00:00 +0000`);
    const list = ["::1", "fe80::2", "fd00::3", "IPv6:::ffff:10.0.0.1", "IPv6:2001:db8::77"].map(x => mk(x.startsWith("IPv6:") ? x : "IPv6:" + x));
    const h = L.findHandoff(list); assert.equal(h.index, 4); assert.equal(h.hop.ip, "2001:db8::77");
});
await test("v6: Received parsing styles", () => {
    const P = L.parseReceived;
    let r = P("from [IPv6:2001:db8::1] by mx.example (Postfix); Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8::1"); assert.equal(r.helo, "ipv6:2001:db8::1".replace("ipv6:", "")); 
    r = P("from [2001:db8::1] (helo=foo.example) by mx.example; Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8::1");
    r = P("from foo.example ([2001:db8::1]:54321 helo=foo.example) by mx.example with esmtps (Exim 4.97); Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8::1"); assert.equal(r.helo, "foo.example");
    r = P("from foo.example (foo.example [2001:db8::1]) by mx.example; Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8::1"); assert.equal(r.rdns, "foo.example");
    r = P("from mail-sor-f41.google.com (mail-sor-f41.google.com. [2607:f8b0:4864:20::f41]) by mx.example; Mon, 1 Jan 2026");
    assert.equal(r.rdns, "mail-sor-f41.google.com"); assert.equal(r.ip, "2607:f8b0:4864:20::f41");
    r = P("from EX1.example ([2001:db8::5]) by EX2.example with Microsoft SMTP Server; Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8::5");
    r = P("from foo.example (foo.example [::ffff:192.0.2.9]) by mx.example; Mon, 1 Jan 2026");
    assert.equal(r.ip, "192.0.2.9");
    r = P("from foo.example (HELO foo.example) (2001:db8::9) by mx.example; Mon, 1 Jan 2026"); // qmail style
    assert.equal(r.helo, "foo.example");
});
await test("v6: SPF a//64, a/24//64, mx//48 dual-cidr", async () => {
    assert.equal((await L.checkSpf("2001:db8:25::5", "v6.example.com", dnsV6)).result, "pass");   // a//64 matches 2001:db8:25::1/64
    assert.equal((await L.checkSpf("2001:db8:26::5", "v6.example.com", dnsV6)).result, "fail");
    assert.equal((await L.checkSpf("2001:db8:99:ff::1", "v6.example.com", dnsV6)).result, "pass"); // mx//48 -> 2001:db8:99::/48
    assert.equal((await L.checkSpf("192.0.2.200", "v6.example.com", dnsV6)).result, "pass");       // a/24 uses A 192.0.2.1
    assert.equal((await L.checkSpf("198.51.100.1", "v6.example.com", dnsV6)).result, "fail");
});
await test("v6: SPF queries only the client's address family (AAAA for v6, A for v4)", async () => {
    const seen = []; const spy = { ...dnsV6, a: n => (seen.push("A " + n), dnsV6.a(n)), aaaa: n => (seen.push("AAAA " + n), dnsV6.aaaa(n)) };
    await L.checkSpf("2001:db8:26::5", "onlyv4.example", spy); assert.deepEqual(seen, ["AAAA onlyv4.example"]);
    seen.length = 0; await L.checkSpf("198.51.100.1", "onlyv4.example", spy); assert.deepEqual(seen, ["A onlyv4.example"]);
    assert.equal((await L.checkSpf("2001:db8::1", "onlyv4.example", dnsV6)).result, "fail"); // v4-only SPF cannot authorize a v6 sender
});
await test("v6: SPF ip6 mechanism with mixed-case/uncompressed network; mapped client vs ip4", async () => {
    assert.equal((await L.checkSpf("2001:db8:abcd::1", "six.example", dnsV6)).result, "pass");
    assert.equal((await L.checkSpf("::ffff:192.0.2.77", "map.example", dnsV6)).result, "pass");
});
await test("v6: reverse DNS nibble PTR, forward-confirm via AAAA, multiple PTRs, HELO match", async () => {
    let r = await L.checkRdns("2001:db8:25::5", "mail6.example.com", dnsV6);
    assert.equal(r.result, "pass"); assert.equal(r.key, "rdnsMatch");
    r = await L.checkRdns("2001:db8:25::5", "other.example.com", dnsV6); assert.equal(r.result, "neutral"); assert.equal(r.subs[1], "mail6.example.com");
    const z = { ...zone, "AAAA mail6.example.com": ["2001:db8:25::6"] };      // first PTR no longer confirms; second (alt6) does not either
    r = await L.checkRdns("2001:db8:25::5", "mail6.example.com", mockDns(z)); assert.equal(r.result, "fail"); assert.equal(r.key, "rdnsNotConfirmed");
    const z2 = { ...z, "AAAA alt6.example.com": ["2001:db8:25::5"] };           // only the 2nd PTR confirms
    r = await L.checkRdns("2001:db8:25::5", "alt6.example.com", mockDns(z2)); assert.equal(r.result, "pass");
});
await test("v6: analyze with trusted AR over IPv6 handoff (internal ULA hop above is skipped)", async () => {
    const r = await L.analyze(v6Headers, dnsV6);
    assert.equal(r.claim.handoff.hop.ip, "2001:db8:25::5"); assert.equal(r.claim.handoff.index, 0);
    assert.equal(r.confirm.spf.result, "pass"); assert.equal(r.confirm.rdns.result, "pass");
    assert.equal(r.confirm.arFlagged.length, 0);
});
await test("v6: analyze fallback (no AR) over IPv6: SPF pass aligned → authentic", async () => {
    const r = await L.analyze(v6NoArHeaders, dnsV6);
    assert.equal(r.confirm.spf.source.type, "own"); assert.equal(r.confirm.spf.result, "pass");
    assert.equal(r.confirm.dmarc.result, "pass"); assert.equal(r.verdict.level, "authentic");
});
await test("AR trust: authserv matching a 'by' host between top and handoff is trusted", async () => {
    const h = { ...v6Headers, received: [
        "from filter.home.example.net (fd00::7) by relay.home.example.net; Thu, 15 Oct 2026 09:00:01 -0500",
        v6Headers.received[0].replace("mx.home.example.net", "gw.home.example.net")],
        "authentication-results": ["other.home.example.net; spf=fail smtp.mailfrom=x@v6.example.com", "gw.home.example.net; spf=pass smtp.mailfrom=bounce@v6.example.com"] };
    const r = await L.analyze(h, dnsV6);
    assert.equal(r.confirm.spf.source.by, "other.home.example.net"); // topmost wins
    assert.equal(r.confirm.arIgnored, 0); assert.equal(r.confirm.arFlagged.length, 0);
});

// ============ synthetic big-sender shapes ============
await test("M365 shape: IPv6 handoff, nameless internal AR ignored (not flagged), multi-signature DKIM, authentic", async () => {
    const a = L.parseAuthResults(m365Headers["authentication-results"][1]);
    assert.equal(a.authserv, ""); assert.deepEqual(a.results.map(r => r.method + "=" + r.result), ["spf=pass", "dkim=pass", "dmarc=pass", "compauth=pass"]);
    const r = await L.analyze(m365Headers, dnsV6);
    assert.equal(r.claim.handoff.hop.ip, "2001:db8:f400:fe::700"); assert.equal(r.claim.handoff.index, 0);
    assert.equal(r.claim.handoff.hop.helo, "nam02-bn1-obe.outbound.protection.outlook.example");
    assert.equal(r.claim.dkim.length, 2);
    assert.equal(r.confirm.dkim.items.length, 2); assert.equal(r.confirm.dkim.items[0].d, "corp.example.com");
    assert.equal(r.confirm.spf.domain, "corp.example.com"); assert.equal(r.confirm.dmarc.policy, "reject");
    assert.equal(r.confirm.arFlagged.length, 0); assert.equal(r.verdict.level, "authentic");
});
await test("Gmail shape: 'by <ipv6-ish>' hop without from is skipped; rdns with trailing dot", async () => {
    const r = await L.analyze(gmailHeaders, dnsV6);
    assert.equal(r.claim.handoff.index, 0); assert.equal(r.claim.handoff.hop.rdns, "mail-sor-f41.google.example");
    assert.equal(r.claim.received[1].hasFrom, false);
    assert.equal(r.confirm.dmarc.policy, "none"); assert.equal(r.verdict.level, "authentic");
});

await test("regression: SES-style mail (Return-Path on bounce domain) with aligned unverified DKIM is not called spoofed on SPF fail alone", async () => {
    const h = { received: ["from a1.smtp-out.example.org (a1.smtp-out.example.org [198.51.100.20]) by mx.home.example.net; Thu, 15 Oct 2026 10:18:45 -0500"],
        from: ["Sender <hello@example.com>"], "return-path": ["<bounce-1@bounce.example.org>"],
        "dkim-signature": ["v=1; d=example.com; s=a; b=x", "v=1; d=example.org; s=b; b=y"] };
    const r = await L.analyze(h, dns);
    assert.equal(r.confirm.spf.result, "none"); assert.equal(r.confirm.dkimUnverifiedAligned, true);
    assert.equal(L.verdict("example.com", { ...r.confirm, spf: { result: "fail" } }).level, "suspicious");
    assert.equal(L.verdict("example.com", { ...r.confirm, spf: { result: "fail" }, dkimUnverifiedAligned: false }).level, "spoofed");
});
// ============ internal (same-tenant Microsoft 365) ============
await test("internal: Received parser handles bare (::1), fe80 with %zone in brackets, bare zone form", () => {
    const r = internalHeaders.received.map(L.parseReceived);
    assert.equal(r[0].ip, "::1"); assert.equal(r[0].by, "byapr19mb2967.namprd19.prod.outlook.com");
    assert.equal(r[1].ip, "2603:10b6:510:22c::21"); assert.equal(r[1].helo, "ph8pr19mb6951.namprd19.prod.outlook.com");
    assert.equal(r[2].ip, "fe80::46a1:74eb:70a2:6ca"); assert.equal(r[2].by, "ph8pr19mb6951.namprd19.prod.outlook.com");
    assert.equal(L.parseReceived("from host.contoso.example (fe80::1%4) by x.outlook.com with mapi; Mon, 1 Jan 2026").ip, "fe80::1");
    assert.equal(L.parseReceived("from host.contoso.example ([fe80::1%eth0]) by x.outlook.com; Mon, 1 Jan 2026").ip, "fe80::1");
    assert.equal(L.normalizeIP("[fe80::1%4]"), "fe80::1");
    assert.ok(!L.isPublicIP("fe80::46a1:74eb:70a2:6ca%4"));
});
await test("internal: authserv-id with version number ('mx.microsoft.com 1') parses", () => {
    const a = L.parseAuthResults(internalHeaders["authentication-results"][0]);
    assert.equal(a.authserv, "mx.microsoft.com"); assert.deepEqual(a.results.map(r => r.method + "=" + r.result), ["dkim=none", "dmarc=none"]);
    assert.ok(L.isMicrosoftHost("mx.microsoft.com") && L.isMicrosoftHost("a.b.prod.outlook.com") && !L.isMicrosoftHost("evil-outlook.com.example.org"));
});
await test("internal: stamp + all-Microsoft path + Microsoft AR → Internal verdict, N/A rows, no DNS", async () => {
    const queries = []; const spy = { ...dnsV6, txt: n => (queries.push(n), dnsV6.txt(n)), a: n => (queries.push(n), dnsV6.a(n)), aaaa: n => (queries.push(n), dnsV6.aaaa(n)), ptr: n => (queries.push(n), dnsV6.ptr(n)) };
    const r = await L.analyze(internalHeaders, spy);
    assert.equal(r.verdict.level, "internal"); assert.equal(r.verdict.key, "reasonInternal");
    assert.equal(r.confirm.internal, true);
    for (const k of ["spf", "dkim", "dmarc", "rdns"]) assert.equal(r.confirm[k].result, "na", k);
    assert.deepEqual(queries, []);
    assert.equal(r.claim.handoff.hop.ip, "2603:10b6:510:22c::21"); // Microsoft front-end hop, not ::1 / fe80
    assert.equal(r.claim.from.domain, "contoso.example");
});
await test("internal: crosstenant-authas alone also counts; stamp value is case-insensitive", async () => {
    const h = { ...internalHeaders }; delete h["x-ms-exchange-organization-authas"]; h["x-ms-exchange-crosstenant-authas"] = ["internal"];
    assert.equal(L.detectInternal(h).state, "internal");
    delete h["x-ms-exchange-crosstenant-authas"]; h["x-ms-exchange-organization-authas"] = ["Anonymous"];
    assert.equal(L.detectInternal(h).state, "none");
});
await test("internal: no stamp, all-Microsoft path → not internal, no warning", async () => {
    const h = { ...internalHeaders }; delete h["x-ms-exchange-organization-authas"]; delete h["x-ms-exchange-crosstenant-authas"];
    const r = await L.analyze(h, dnsV6);
    assert.notEqual(r.verdict.level, "internal"); assert.equal(r.confirm.internalStampWarning, null);
});
await test("internal: stamp + external hop → stamp ignored completely (no warning, no docking, normal analysis)", async () => {
    assert.deepEqual(L.detectInternal(forgedInternalExternalHop), { state: "none" });
    const r = await L.analyze(forgedInternalExternalHop, dnsV6);
    assert.notEqual(r.verdict.level, "internal"); assert.ok(!r.confirm.internal);
    assert.equal(r.confirm.internalStampWarning, null);
    assert.notEqual(r.verdict.key, "reasonDockedInternalStamp"); assert.notEqual(r.verdict.key, "reasonMixedInternalStamp");
    assert.equal(r.confirm.dmarc.source.type, "ar"); // the Authentication-Results rules apply as for any other mail
});
await test("regression: outbound M365 mail (IPv4 handoff) with Internal stamp, received by an external server → Likely authentic, no warning", async () => {
    const r = await L.analyze(outboundM365Ipv4, dnsV6);
    assert.equal(r.verdict.level, "authentic"); assert.equal(r.verdict.key, "reasonDmarcPass");
    assert.equal(r.confirm.internalStampWarning, null); assert.ok(!r.confirm.internal);
    assert.equal(r.confirm.arFlagged.length, 0);
    assert.equal(r.claim.handoff.index, 0); assert.equal(r.claim.handoff.hop.ip, "203.0.113.40");
    assert.equal(r.confirm.spf.result, "pass"); assert.equal(r.confirm.dkim.result, "pass"); assert.equal(r.confirm.dmarc.result, "pass");
    assert.equal(r.confirm.spf.source.by, "mx.example.net");
});
await test("regression: outbound M365 mail (IPv6 handoff) with Internal stamp → Likely authentic, no warning", async () => {
    const r = await L.analyze(outboundM365Ipv6, dnsV6);
    assert.equal(r.verdict.level, "authentic"); assert.equal(r.confirm.internalStampWarning, null);
    assert.equal(r.claim.handoff.hop.ip, "2001:db8:f400:fe::700");
});
await test("outbound M365 mail without Authentication-Results: stamp still ignored, own-DNS fallback, no warning", async () => {
    const h = { ...outboundM365Ipv4 }; delete h["authentication-results"];
    const r = await L.analyze(h, dnsV6);
    assert.equal(r.confirm.internalStampWarning, null); assert.equal(r.confirm.spf.source.type, "own");
    assert.notEqual(r.verdict.level, "internal");
});
await test("internal NEGATIVE: stamp + Microsoft path but foreign Authentication-Results → not Internal, warning", async () => {
    assert.deepEqual(L.detectInternal(forgedInternalForeignAR), { state: "forged", authserv: "mx.evil.example.org" });
    const r = await L.analyze(forgedInternalForeignAR, dnsV6);
    assert.notEqual(r.verdict.level, "internal"); assert.equal(r.confirm.internalStampWarning.authserv, "mx.evil.example.org");
    assert.equal(r.verdict.level, "suspicious"); // AR claims dmarc=pass, but the forged stamp docks authentic to suspicious
    assert.equal(r.verdict.key, "reasonDockedInternalStamp");
});
await test("internal NEGATIVE: Microsoft hostnames but public Microsoft IPv4 hop (cross-tenant) is not an internal path", () => {
    const h = { ...internalHeaders, received: ["from NAM_obe.outbound.protection.outlook.example (x.outbound.protection.outlook.com [40.107.95.71]) by BYAPR19MB2967.namprd19.prod.outlook.com with ESMTPS; Thu, 15 Oct 2026 10:42:00 +0000"] };
    assert.equal(L.detectInternal(h).state, "none"); // stamp ignored on a non-internal path
});
await test("internal: M365 inbound from the internet without the stamp is unaffected (still Suspicious/authentic by normal rules)", async () => {
    const r = await L.analyze(m365Headers, dnsV6); assert.equal(r.verdict.level, "authentic");
});

// Regression: M365 -> private server. The message carries the receiving server's AR (pass) AND Microsoft's upstream stamp
// ("mx.microsoft.com 1; dkim=none (message not signed); dmarc=none"). The stamp must never override the pass or be flagged.
const arRecv = "mx.example.net; spf=pass smtp.mailfrom=contoso.example; dkim=pass header.d=contoso.example header.s=selector1; dmarc=pass (p=reject) header.from=contoso.example";
const arMsStamp = "mx.microsoft.com 1; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=contoso.example;";
for (const [label, order] of [["receiving server's AR on top", [arRecv, arMsStamp]], ["Microsoft stamp on top", [arMsStamp, arRecv]]]) {
    await test("upstream Microsoft AR stamp does not hide pass results (" + label + ")", async () => {
        const r = await L.analyze({ ...outboundM365Ipv4, "authentication-results": order }, dnsV6);
        assert.equal(r.confirm.spf.result, "pass");
        assert.equal(r.confirm.dkim.result, "pass");
        assert.equal(r.confirm.dmarc.result, "pass");
        assert.equal(r.confirm.arFlagged.length, 0);
        assert.equal(r.confirm.arIgnored, 1);
        assert.equal(r.verdict.level, "authentic");
    });
}
await test("upstream Microsoft AR stamp alone: falls back to own checks, not 'none' from the stamp", async () => {
    const r = await L.analyze({ ...outboundM365Ipv4, "authentication-results": [arMsStamp] }, dnsV6);
    assert.equal(r.confirm.arFlagged.length, 0);
    assert.equal(r.confirm.dkim.source.type, "own");
    assert.notEqual(r.confirm.dmarc.source.type, "ar");
});
await test("Microsoft AR still trusted when Microsoft is the recipient (M365 inbound fixture unchanged)", async () => {
    const r = await L.analyze(m365Headers, dnsV6);
    assert.equal(r.confirm.spf.source.type, "ar");
});

await test("manifest defines browser_specific_settings.gecko id, strict_min_version, and strict_max_version", async () => {
    const { readFileSync } = await import("node:fs");
    const m = JSON.parse(readFileSync(new URL("../src/manifest.json", import.meta.url)));
    assert.ok(m.browser_specific_settings && m.browser_specific_settings.gecko, "missing browser_specific_settings.gecko");
    assert.equal(m.browser_specific_settings.gecko.id, "receivedheaderinspector-en@dowlen.net");
    assert.equal(m.browser_specific_settings.gecko.strict_min_version, "128.0");
    assert.equal(m.browser_specific_settings.gecko.strict_max_version, "160.*");
});

await test("SpoofCheck v1.7.0 manifest icons and locale messages are valid and present", async () => {
    const { readFileSync, existsSync } = await import("node:fs");
    const m = JSON.parse(readFileSync(new URL("../src/manifest.json", import.meta.url)));
    assert.equal(m.version, "1.7.0");
    for (const sz of ["16", "32", "48", "64", "128"]) {
        assert.equal(m.icons[sz], `images/icon-${sz}.png`);
        assert.equal(m.message_display_action.default_icon[sz], `images/icon-${sz}.png`);
        assert.ok(existsSync(new URL(`../src/images/icon-${sz}.png`, import.meta.url)), `missing icon-${sz}.png`);
    }
    assert.ok(existsSync(new URL("../src/images/icon.svg", import.meta.url)), "missing icon.svg");
    const en = JSON.parse(readFileSync(new URL("../src/_locales/en/messages.json", import.meta.url)));
    const fr = JSON.parse(readFileSync(new URL("../src/_locales/fr/messages.json", import.meta.url)));
    assert.equal(en.extName.message, "SpoofCheck — Sender & Header Inspector");
    assert.equal(en.actionTitle.message, "SpoofCheck");
    assert.equal(fr.extName.message, "SpoofCheck — Vérificateur d'expéditeur et d'en-têtes");
    assert.equal(fr.actionTitle.message, "SpoofCheck");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
