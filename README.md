# phishing-detector

A small, offline tool that scores supplied email text or a URL for
phishing signals — and explains its reasoning in plain language.

It is defensive analysis only. It never sends mail, never fetches an
arbitrary URL, and never visits a live phishing site. It reads the text
you hand it, checks it against a set of known red flags, and returns a
score from 0–100, a risk level (Low / Medium / High), and a list of
reasons. A high score is a warning to stop and check, not proof that
something is malicious — and a low score is never a guarantee that
something is safe.

## What it checks

- **Suspicious links** — plain HTTP, `@` in the URL authority, non-standard ports
- **Mismatched display domains** — link text shows one domain (e.g. `paypal.com`) but the href goes somewhere else, in Markdown `[text](url)` or HTML `<a href>` form
- **Urgency keywords** — "urgent", "account suspended", "act now", "verify now", and similar pressure language (capped, so urgency alone can't max the score)
- **Suspicious attachment types** — `.exe`, `.scr`, `.bat`, `.js`, `.ps1`, and friends mentioned in the text; archives (`.zip`, `.rar`) get a smaller nudge
- **URL shorteners** — `bit.ly`, `tinyurl.com`, `t.co`, and others that hide the real destination
- **IP-literal hosts** — a bare IP address instead of a domain name
- **Lookalike / punycode hints** — `xn--` punycode hosts, non-ASCII characters in a host, and domains that mention a well-known brand without being that brand's domain
- **Excessive subdomains** — deep chains like `a.b.c.d.example.com`
- **Volume** — many links packed into a single message

## How to run it

Requires Python 3.8+ and nothing else — standard library only, so there
is nothing to install (see `requirements.txt`).

```bash
# Score a fake example email (included, safe to run)
python main.py --file samples/phishing_example.txt

# Score a benign example for comparison
python main.py --file samples/legit_example.txt

# Score a single URL string
python main.py --url "https://bit.ly/fake-example-123"

# Score arbitrary text, with JSON output
python main.py --text "URGENT: account suspended, see invoice.exe" --json

# Or as a module
python -m phishing_detector --help
```

Example output for the phishing sample:

```
Score: 100/100
Risk:  High
URLs found:
  - https://evil-example.com/login?session=123
  - https://bit.ly/fake-example-123
Reasons:
  - Display domain mismatch: text shows 'paypal.com' but link goes to 'evil-example.com'
  - URL shortener hides the real destination: bit.ly
  - Suspicious attachment type mentioned: *.exe
  - Urgency / pressure language: 'urgent'
  ...
```

## Project layout

```
main.py                          # CLI entry point
phishing_detector/
  __init__.py
  __main__.py                    # `python -m phishing_detector`
  cli.py                         # argument parsing and output
  detector.py                    # scoring logic (the interesting part)
tests/
  test_phishing_detector.py      # unittest suite
samples/
  phishing_example.txt           # clearly fake phishing-style email
  legit_example.txt              # clearly fake benign email
requirements.txt                 # empty — stdlib only
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## What I learned building this

The useful part of a detector like this isn't the score — it's the
reasons list. A single signal is almost never decisive: URL shorteners
are used by legitimate newsletters, urgency language shows up in real
billing mail, and a `.zip` attachment is routine. The signal is in the
combination — a mismatched display domain *plus* a shortener *plus*
pressure language *plus* an executable attachment is a very different
picture from any one of those alone. That's also why the weights are
capped and combined rather than letting one check dominate, and why
the tool reports what it found instead of just saying "phishing" or
"safe".

The other lesson: keep the analysis offline and input-only. The moment
a "detector" starts fetching the URLs it is asked about, it becomes a
tool that can be pointed at live malicious infrastructure — and at
victims. Reading supplied text is enough to catch the structural
tells, and it keeps the tool safe to run on any machine.

## Limits

- This is a heuristic scorer, not a verdict engine. Real phishing
  pages can look clean to every check here, and legitimate mail can
  trip several of them.
- It does not check domain age, DNS records, or blocklists, and it
  does not render HTML or follow redirects — by design.
- When in doubt, verify through a separate channel you already trust
  (type the site address yourself, call the company on a number from
  its real site), and never open an unexpected attachment.

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
