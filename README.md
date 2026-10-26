# SpoofCheck — Sender & Header Inspector

Thunderbird and Betterbird add-on that verifies who an email is really from by inspecting `Received` hops, `Authentication-Results`, SPF, DKIM, DMARC, and reverse DNS.

*(Formerly **ReceivedHeaderInspector-EN**)* — English-first fork and evolution of the Thunderbird add-on **ReceivedHeaderInspector** by **Olivier Poujade (Olivier P.)**.
Original project: https://github.com/PoujadeOlivier/ReceivedHeaderInspector
(listed on addons.thunderbird.net under the MIT/X11 license). All credit for the original idea and the first versions goes to the original author.

Works in Thunderbird 128+ (`128.0` – `160.*`) and Betterbird.

## Download and install
1. Download the latest `.xpi` (`spoofcheck-1.7.0-tb.xpi`) from the [Releases page](https://github.com/scottdd/SpoofCheck/releases/latest).
2. In Thunderbird/Betterbird open **Add-ons and Themes**, click the gear menu, choose **Install Add-on From File**, and pick the `.xpi`.
3. Approve the permissions (reading the displayed message, and DNS-over-HTTPS access to the resolvers listed below).

Installing a newer version over an older one (including earlier `ReceivedHeaderInspector-EN` releases) updates it seamlessly in place. The add-on ID remains `receivedheaderinspector-en@dowlen.net`, so existing installations upgrade automatically and it can sit next to the original French add-on.

## What it does
Open a message and click the **SpoofCheck** button in the message toolbar. The popup answers one question: *is this message really from who it says it is?* It is organized into three sections:

- **Claim** shows what the message claims: Subject, From (name, address, domain), Return-Path domain, DKIM signing domain(s) (`d=`), the handoff server (HELO name and IP of the server that delivered the message to your mail server) and the Sender/X-Sender header.
- **Confirm** gives a pass/fail badge for each claim: SPF, DKIM, DMARC (including alignment with the From domain and the published policy) and reverse DNS of the handoff IP, forward-confirmed against the HELO name. Each row says where the result came from.
- **Verdict** sums it up as **Likely authentic**, **Suspicious** or **Likely spoofed**, with a one-line reason.

Claim and Confirm rows start collapsed to one line and expand when clicked. A collapsible **Delivery path** lists every hop from the `Received` headers.

### Screenshots (example data)
A message that checks out, with Handoff server and Reverse DNS rows expanded:

![Likely authentic, rows expanded](docs/img/authentic-expanded.png)

The same message with everything collapsed (the default view):

![Likely authentic, collapsed](docs/img/authentic.png)

A spoofed message with no `Authentication-Results`, checked with the add-on's own DNS lookups:

![Likely spoofed](docs/img/spoofed.png)

A message carrying an untrusted, possibly forged `Authentication-Results` header:

![Untrusted Authentication-Results warning](docs/img/forged-auth-results.png)

An internal message between two users of the same Microsoft 365 tenant. It never left Exchange Online, so SPF, DKIM and DMARC show as N/A:

![Internal message (same organization)](docs/img/internal.png)

### How results are decided
- **Authentication-Results first.** The add-on trusts the topmost `Authentication-Results` header, or one whose server name matches the server in the topmost `Received` header, because your own mail server saw the real connection. Results are shown as "from Authentication-Results by <server>".
- **Own checks as fallback.** If a result is missing, the add-on does its own DNS checks (SPF evaluation, DMARC record and alignment, reverse DNS) and labels them "own DNS check via <resolver>". DKIM signatures are not verified locally in this case and show as neutral.
- **Internal Microsoft 365 mail.** Mail between two users of one Microsoft 365 tenant never leaves Exchange Online. It is shown as "Internal message (same organization)", with SPF/DKIM/DMARC/reverse DNS as grey N/A rows, only when Exchange's `X-MS-Exchange-Organization-AuthAs: Internal` stamp is present **and** every `Received` hop is a Microsoft hop **and** any `Authentication-Results` header comes from Microsoft. That stamp is added in the sender's tenant and stays on the message when Microsoft 365 relays it to outside recipients, so as soon as the delivery path includes any non-Microsoft hop the stamp is ignored completely (no warning, no change to the verdict) and the message is checked like any other mail. If the path is all-Microsoft but an `Authentication-Results` header comes from a non-Microsoft server, the message is not called internal: it is checked normally, capped at "Suspicious", and an amber warning row is shown.
- **Forged-header warning.** An extra `Authentication-Results` header from a different organization than your mail server is flagged with an amber warning and lowers a "Likely authentic" verdict to "Suspicious".

### DNS lookups
Own checks use DNS over HTTPS with the JSON API, trying these resolvers in order and falling back on timeout (3 s), network or HTTP errors, or SERVFAIL: Cloudflare, NextDNS, AdGuard (unfiltered), DNS.SB, Google. "Domain does not exist" is treated as a real answer. Lookups send the sender's domains and the handoff IP to the resolver that answers. If your mail server supplies a trusted `Authentication-Results` header, little or nothing needs to be looked up.

## Languages
English is the default UI language (WebExtension i18n); French strings are in `_locales/fr`. More languages are planned, see [TODO.md](TODO.md).

## Versions
- **1.7.0:** rebranded from `ReceivedHeaderInspector-EN` to **SpoofCheck — Sender & Header Inspector** (`SpoofCheck` toolbar button) with a new high-contrast vector & multi-size PNG Header Inspector Loupe icon (`16px`–`128px`, readable on both dark and light toolbars). Keeps add-on ID `receivedheaderinspector-en@dowlen.net` for seamless in-place upgrades.
- **1.6.7:** declare explicit `strict_max_version` (`160.*`) alongside `strict_min_version` (`128.0`) in `browser_specific_settings.gecko` for Thunderbird/Betterbird add-on compatibility checks.
- **1.6.6:** fix: DKIM/DMARC no longer shown as "none" (or a false untrusted-header warning) on Microsoft 365 mail relayed to a non-Microsoft server; Microsoft's pre-signing `mx.microsoft.com` Authentication-Results stamp is now treated as an upstream stamp and ignored.
- **1.6.5:** fix: Exchange's `AuthAs: Internal` stamp on mail relayed outbound by Microsoft 365 no longer triggers a false "Suspicious"; the stamp now only matters for all-Microsoft (internal) delivery paths.
- **1.6.4:** new "Internal message (same organization)" verdict for same-tenant Microsoft 365 mail; SPF fail plus aligned but locally unverifiable DKIM is now Suspicious instead of Likely spoofed.
- **1.6.3:** IPv6 hardening (IPv4-mapped addresses, handoff selection, PTR checks), better Authentication-Results trust, Exchange Online header shapes.
- **1.6.2:** resolver fallback list, forged `Authentication-Results` warning with verdict downgrade.
- **1.6.1:** new Claim / Confirm / Verdict panel, `Authentication-Results` parsing, own SPF/DMARC/reverse-DNS checks.
- **1.6.0:** English-first fork (i18n, new name and ID).

## Development
Source is in `src/`. Tests need only Node and no network:
```
node test/run-tests.js
```
Build the installable package (the manifest must be at the top level of the zip):
```
cd src && python3 -m zipfile -c ../dist/spoofcheck-<version>-tb.xpi .
```
Documentation screenshots are rendered with `test/screenshot.py` (Playwright and Chrome, mocked mail data). Planned work is tracked in [TODO.md](TODO.md).

## Known limitations
- If your mail server does not add its own `Authentication-Results`, a forged one at the top of the message could be trusted.
- No local DKIM signature verification in the fallback path.
- The organizational-domain check is an approximation, not the full Public Suffix List.
- SPF macros are not supported and `ptr` never matches.

## Examples from the original project
![Example 01](Ressources/ExempleSpoofing01.jpg)
![Example 02](Ressources/ExempleSpoofing02.jpg)

## License
MIT. See [LICENSE](LICENSE). Original work © Olivier Poujade; fork changes © Scott Dowlen.
