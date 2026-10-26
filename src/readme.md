### Version 1.7.0 (SpoofCheck — formerly ReceivedHeaderInspector-EN)
- Rebranded from `ReceivedHeaderInspector-EN` to **SpoofCheck — Sender & Header Inspector** (`SpoofCheck` message toolbar button) while keeping add-on ID `receivedheaderinspector-en@dowlen.net` for seamless in-place updates.
- New high-contrast Header Inspector Loupe icon (`images/icon.svg` and `16px`, `32px`, `48px`, `64px`, `128px` PNGs) designed for both dark and light Thunderbird/Betterbird toolbars.
- Preserves full attribution to Olivier Poujade's original MIT-licensed `ReceivedHeaderInspector`.

### Version 1.6.7 (English fork)
- Manifest: declare explicit `strict_max_version` (`160.*`) alongside `strict_min_version` (`128.0`) in `browser_specific_settings.gecko` so Thunderbird/Betterbird compatibility checks verify version bounds.

### Version 1.6.6 (English fork)
- Fix: DKIM and DMARC shown as "none" (or a false "untrusted Authentication-Results" warning) on mail sent from Microsoft 365 to a non-Microsoft server. Exchange Online leaves its own upstream stamp (`Authentication-Results: mx.microsoft.com 1; dkim=none (message not signed); dmarc=none`) on the message, written before DKIM signing. When the receiving server is not Microsoft and the path includes Microsoft hops, Microsoft-authserv AR headers are now set aside as upstream stamps (ignored, not flagged) before the topmost header is picked, so the receiving server's own SPF/DKIM/DMARC results are used.

### Version 1.6.5 (English fork)
- Fix: false "Suspicious" on mail sent from Microsoft 365 to an outside server. Exchange Online adds `X-MS-Exchange-Organization-AuthAs: Internal` (and `x-ms-exchange-crosstenant-authas`) in the sender's tenant and the stamp stays on the message when it is relayed outbound. The stamp now only matters for declaring "Internal message": if the delivery path contains any non-Microsoft hop it is ignored completely (no warning row, no verdict change) and SPF/DKIM/DMARC are evaluated as for any other mail. A forged stamp therefore gains an outsider nothing.
- Unchanged: an all-Microsoft path with an `Authentication-Results` header from a non-Microsoft server is still not called internal and shows a warning.
- Removed the now-unused "internal stamp, path not internal" warning strings (English and French).
- Tests: 62, including regression fixtures shaped like outbound Microsoft 365 mail received by an external server (IPv4 and IPv6 handoff).

### Version 1.6.4 (English fork)
- New verdict "Internal message (same organization)": a message between two users of one Microsoft 365 tenant never crosses the internet, so SPF/DKIM/DMARC/reverse DNS are shown as grey "N/A (internal)" rows. It is declared only when Exchange's `X-MS-Exchange-Organization-AuthAs: Internal` stamp (or `x-ms-exchange-crosstenant-authas: Internal`) is present, every Received hop is a Microsoft hop (Microsoft host names; ::1, fe80::, 2603:10b6:: or 2a01:111:: addresses only), and any Authentication-Results header comes from Microsoft (for example `mx.microsoft.com 1`).
- If the path is all-Microsoft but an Authentication-Results header comes from a non-Microsoft server, the message is not called internal: it is checked normally, capped at "Suspicious", and a warning row explains why.
- Received parser: handles bare `(::1)` and fe80 addresses with a zone id (`fe80::1%4`).
- Verdict: SPF fail together with an aligned DKIM signature that cannot be verified locally is now "Suspicious" rather than "Likely spoofed".
- Tests: 59 (internal message fixture and negative cases).

### Version 1.6.3 (English fork)
- IPv6 audit and fixes: IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are treated as IPv4 for SPF, reverse DNS and private-address detection; multicast ranges are skipped when picking the handoff hop; bracketed `[IPv6:...]` HELO literals are cleaned up for display.
- Reverse DNS now forward-confirms every PTR name (up to 5), not just the first, and trailing dots in header rDNS names are removed.
- Authentication-Results trust: a header is trusted when its authserv-id matches the `by` host of any hop from the top down to the handoff hop (not only the topmost one). Headers with no authserv-id (Exchange Online internal stamps) are ignored without raising the forged-header warning.
- Popup: DKIM rows from Authentication-Results no longer show "d=?" when the header has no domain.
- Tests: IPv6 parsing/ranges/PTR/SPF dual-CIDR (`a/24//64`), Received styles (Postfix, Exim, Microsoft, Google), M365- and Gmail-shaped samples (49 tests).

### Version 1.6.2 (English fork)
- DNS-over-HTTPS resolvers now tried in order with fallback: Cloudflare, NextDNS, AdGuard (unfiltered), DNS.SB, Google (3 s timeout; fallback on network/HTTP error or SERVFAIL, not on NXDOMAIN). Each own-DNS-check note names the resolver that answered. Host permissions match this list exactly.
- Warning row and verdict downgrade when an untrusted Authentication-Results header is present. AR headers whose authserv-id shares the organizational domain of the trusted one (internal multi-hop) are not flagged.

### Version 1.6.1 (English fork)
- Redesigned popup: Claim (From, Return-Path, DKIM d=, handoff server, Sender), Confirm (SPF, DKIM, DMARC, reverse DNS with pass/fail badges and source), Verdict, collapsible delivery path.
- Uses trusted Authentication-Results when present; otherwise own DNS-over-HTTPS checks (SPF evaluation, DMARC alignment). Reverse DNS is always checked locally.
- IPv6 support in Received parsing. Removed raw SPF/TXT record dump. Resolver URL configurable in dns.js (Google or Cloudflare).

### Version 1.6.0 (English fork)
- English-first fork: UI localized via WebExtension i18n (English default, French kept); comments translated; new name and ID. No functional changes.

### Version 1.5
- manifest.json fix.

### Version 1.4
- Uses the dns.google API. This version adds checks of the sending server and of the sender's email domain via Google's public DNS API, enabling security checks on that address (e.g. checking SPF records or getting the IP associated with a sending domain).

### Version 1.3
- Renamed for clarity.

### Version 1.2
- **Code optimization**: simplified and refactored `popup.js` for readability and maintainability, with no change in behavior or features.

### Version 1.1
- First stable version of **SendInspecteur**: displays transit servers and checks sender domains.
- Helps detect inconsistencies and prevent phishing and spoofing.

## Received Header Inspector
An extension designed to help users detect spoofing and phishing in their email. It displays the transit servers associated with received messages, so you can verify senders' legitimacy and spot inconsistencies in sender information.

### Main features
- **Transit server display**: see the sending servers of received emails.
- **Sender domain check**: compare the email address domain with the transit servers to detect inconsistencies.
- **Phishing protection**: use this information to spot suspicious messages and avoid spoofing scams.

### How does it work?
Open an email and click the add-on's button in the message toolbar; it analyzes the message headers to extract transit server information and displays it so you can check consistency with the sender's domain.

### Original author
Olivier Poujade (Olivier P.) - https://github.com/PoujadeOlivier/ReceivedHeaderInspector
