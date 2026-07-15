

# Phishing Spotter 🎣🔍

A chatbot-style tool that scans pasted emails or messages for common phishing red flags using rule-based pattern matching. Built as a bridge between web development and applied security — no ML, no external APIs, just regex, some domain heuristics, and a chat UI.

## What it checks for

- **Urgency & pressure language** — "act now," "account suspended," "within 24 hours"
- **Credential/data requests** — asks to confirm passwords, card numbers, OTPs
- **Spoofed & lookalike domains** — flags when a message names a brand (PayPal, banks, etc.) but the link points to a different or suspiciously similar domain, using edit-distance comparison
- **Mismatched links** — if pasted as raw HTML, compares the visible link text against where the `href` actually goes
- **Other signals** — shortened URLs, executable attachment bait, "you've won" offers, generic greetings, threatening/legal language

Each result comes with a risk gauge (Low → Critical), a breakdown of every flag found with plain-English reasoning, and a highlighted version of the original message showing exactly what triggered each flag.

## Try it

Three built-in samples let you demo it without needing a real phishing email on hand: a phishing sample, a clean email, and an HTML sample with a mismatched link.

## Tech

Vanilla HTML, CSS, and JavaScript — no build step, no dependencies. `index.html`, `styles.css`, and `script.js`.

## Run it locally

Clone the repo and open `index.html` in a browser, or visit the live version:
👉 https://makene2699.github.io/phishing-spotter/

## Why this project

Phishing detection is a good showcase for combining software development with security thinking: parsing untrusted text, reasoning about what makes a URL suspicious, and designing a UI that communicates risk clearly rather than just flagging "good/bad."

## Limitations

This is heuristic pattern-matching, not a production security tool. It won't catch everything, and a clean result isn't a guarantee a message is safe. Always verify through channels you look up yourself, not links or numbers provided in the message.
