# Desisherlock

A Linux command-line reconnaissance, vulnerability-assessment, and
reporting toolkit for security professionals. Desisherlock brings together
the kind of checks `nmap`, `dig`, `whois`, and public services like SSL
Labs' or Mozilla Observatory's checkers already do, under one set of short
commands and one interactive shell.

> **Authorized use only.** See [DISCLAIMER.md](DISCLAIMER.md) before using
> this tool against any target. This is a recon/assessment/reporting tool
> - it contains no exploit modules, payload generators, or brute-forcers,
> and never will (see the disclaimer for the exact scope boundary).

## Why "Desisherlock"?

Recon work is detective work: gather clues (open ports, headers, DNS
records, certificates), reason about what they imply, and write up your
findings. Desisherlock aggregates that workflow into one tool.

---

## Setup, step by step

**Requirements:** Linux, Python 3.8+. No root/sudo is ever required — port
scanning uses plain TCP connect scanning (`socket.connect_ex`), never raw
SYN packets.

**1. Get the code.**

```bash
git clone https://github.com/<your-username>/<your-repo>.git Desisherlock
cd Desisherlock
```

(Or unzip it if you were given a `.zip` instead of a git URL.)

**2. Run the installer.**

```bash
bash install.sh
```

(`bash install.sh` works no matter what — use it instead of `./install.sh`
if you ever see `Permission denied`; see Troubleshooting below for why.)

This checks your Python/pip versions and runs `pip install --user`, so
nothing is installed system-wide and no `sudo` is ever needed. **No
further setup is required** — at the end of the install, the script
detects whether `Desisherlock` is runnable yet, and if it isn't (i.e. its
install folder isn't already on your `PATH`), it hands your terminal off
into a fresh shell with the right `PATH` already set. You don't need to
run `source ~/.bashrc`, open a new terminal, or edit any config yourself —
by the time `install.sh` finishes, you're sitting at a working prompt.

**3. Confirm it works.**

```bash
Desisherlock --version
```

You should see a version number immediately, in the same terminal, no
extra steps. If instead you get `Desisherlock: command not found`, see
**Troubleshooting** below.

**4. Launch it.**

```bash
Desisherlock
```

with no arguments drops you into the interactive shell (banner + a
`Desisherlock ~$` prompt). Or run a single command and exit — see
**Command reference** below.

**To uninstall later:**

```bash
./uninstall.sh
```

---

## Troubleshooting: "Permission denied" running install.sh

```bash
chmod +x install.sh uninstall.sh
./install.sh
```

This happens when the executable bit was stripped in transit (common
after a GitHub web upload rather than `git clone` of a properly pushed
repo). `bash install.sh` also works regardless of the executable bit if
you'd rather not `chmod`.

## Troubleshooting: "externally-managed-environment" error from pip

Recent Debian/Ubuntu (24.04+) block plain `pip install` system-wide (PEP
668). `install.sh` already handles this for you by retrying with
`--break-system-packages` scoped to your user install — you shouldn't
need to do anything manually here. If you're installing by hand instead
of via `install.sh`, use:

```bash
pip install --user --upgrade --ignore-installed . --break-system-packages
```

## Troubleshooting: "command not found"

`install.sh` normally fixes `PATH` for you automatically (see step 2
above) — you should not need anything in this section. It only applies
if you installed non-interactively (piped the script into `bash`, ran it
from a script/CI job with no terminal attached) or ran `pip install`
directly instead of using `install.sh`, since in those cases there's no
terminal for the installer to hand off into.

First, confirm `pip` actually finished installing Desisherlock: if
`install.sh` never got to run successfully (e.g. it hit the
"Permission denied" or "externally-managed-environment" errors above),
fix those first — no amount of `PATH` fiddling will help if the package
was never installed.

Once you've confirmed `install.sh` printed "Install succeeded.", fix the
`PATH` with:

```bash
export PATH="$HOME/.local/bin:$PATH"
Desisherlock --version
```

(If you installed while logged in as `root`, use `/root/.local/bin`
instead of `$HOME/.local/bin`.)

Once that works, make it permanent so you don't have to repeat it every
new terminal:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

If you're not sure which folder pip used, ask it directly:

```bash
python3 -m site --user-base
```
— the scripts are in the `bin` subfolder of whatever that prints.

---

## Usage

Desisherlock works two ways, using the exact same flags in both:

**One-shot CLI** — runs a single command and exits, safe for scripts and
pipes:

```bash
Desisherlock -S 192.168.1.10
```

**Interactive shell** — run `Desisherlock` with no arguments to get a
banner and a REPL prompt (`Desisherlock ~$ `) that accepts the same
flags, one command per line, e.g.:

```
Desisherlock ~$ -S 192.168.1.10
Desisherlock ~$ -hash 5f4dcc3b5aa765d61d8327deb882cf99
Desisherlock ~$ -report md
Desisherlock ~$ close
```

Inside the shell you also get a few bare convenience words:

| Word | Effect |
|---|---|
| `help` | Show full command help |
| `clear` | Clear the screen |
| `version` | Show version |
| `banner` | Re-print the startup banner |

And several ways to exit: `close`, `exit`, `quit`, `bye`, `q` (or Ctrl-D /
Ctrl-C).

The console script is registered as both `Desisherlock` and `desisherlock`
- use whichever case you remember.

The first time you run any command that actually touches the network,
you'll see a one-time authorized-use notice (press Enter to continue).
It's recorded in `~/.desisherlock/config.json` so it only ever appears
once, ever, across both modes. Non-network commands (`--version`, `-h`,
`-list`) never trigger it.

---

## Command reference

| Flag | Behavior |
|---|---|
| `-S, --scan <target>` | Liveness check + scan of a curated "top ports" list + banner grab; open ports are labeled with their IANA-registered service name |
| `-port, --port-scan <target>` | Full port scan |
| `-p, --ports <spec>` | Port spec for `-port`: `top` (default), `1-65535`, `22,80,443`, or mixed, e.g. `22,100-200,443` |
| `--threads <n>` | Thread count for port scanning (default from config, normally 100) |
| `-Vc, --vuln-check` | Combine with `-S`/`-port` to cross-check found banners against CVEs; or standalone via `--product`/`--pversion`, or a free-text target/keyword |
| `--product <name>` | Product name for a standalone `-Vc` lookup |
| `--pversion <version>` | Product version for a standalone `-Vc` lookup |
| `-CVSS <CVE-ID\|keyword>` | Direct NVD CVE/CVSS lookup |
| `-web <url>` | Security header analysis + common exposed-path check |
| `-ssl <host[:port]>` | Certificate + cipher inspection, including expiry status (`days_until_expiry`, `expired`, `expires_soon`); works against self-signed/expired certs too; default port 443 |
| `-dns <domain>` | DNS record enumeration (A/AAAA/MX/TXT/NS/CNAME/SOA) + SPF/DMARC/DNSSEC posture + subdomain brute force |
| `--wordlist <path>` | Override the bundled subdomain wordlist for `-dns` |
| `-hash <string>` | Hash *format identification* only — no cracking |
| `-whois <domain>` | WHOIS registration lookup |
| `-audit <target>` | Run `-S` + `-ssl` + `-dns` + `-web` + `-whois` against one target back-to-back and auto-save a Markdown report - the fastest way to get a full picture of a target in one command |
| `-report [md\|html\|json\|csv]` | Render the session's accumulated findings (default `md`), saved under `~/.desisherlock/reports/` |
| `-o, --output <file>` | Dump the current command's raw result as JSON to `<file>` |
| `-configure` | Interactively set an NVD API key and default threads/timeout |
| `-update` | Check for/apply updates |
| `-list`, `-h`, `--help` | Show help |
| `--version` | Show version |
| `-t, --target <target>` | Explicit target (alternative to the positional target argument) |
| `-y, --yes` | Skip the authorization notice for this run |
| `--no-banner` | Suppress the startup banner (interactive shell only) |

### Examples

```bash
# Liveness check + top-ports scan with banner grabbing
Desisherlock -S example.com

# Full port scan of a range, with more threads
Desisherlock -port 192.168.1.10 -p 1-1024 --threads 200

# Scan + auto cross-check discovered service banners against CVEs
Desisherlock -S 192.168.1.10 -Vc

# Standalone CVE/CVSS lookups
Desisherlock -CVSS CVE-2021-44228
Desisherlock -Vc --product openssh --pversion 7.4

# TLS certificate + cipher inspection
Desisherlock -ssl example.com:443

# DNS records + subdomain brute force
Desisherlock -dns example.com
Desisherlock -dns example.com --wordlist /path/to/bigger-list.txt

# Web header + exposed-path check
Desisherlock -web https://example.com

# Hash format identification (never cracks anything)
Desisherlock -hash 5f4dcc3b5aa765d61d8327deb882cf99

# WHOIS lookup
Desisherlock -whois example.com

# Full audit: scan + ssl + dns + web + whois in one shot, auto-saves a report
Desisherlock -audit example.com

# Save the current session's findings as a report
Desisherlock -report md
Desisherlock -report html
Desisherlock -report json
Desisherlock -report csv

# Dump one command's raw JSON result to a file
Desisherlock -S example.com -o scan_result.json
```

### A note on DNS/email checks and timeouts

`-dns` reports `spf`, `dmarc`, and `dnssec` as separate objects, each with
their own `error` field. A populated `error` (e.g. "TXT query timed out")
means the check couldn't get a definitive answer - it is deliberately
**not** the same as `"present": false`, since claiming "no SPF record"
when the query actually just timed out would be a false negative, not a
real finding. If you see timeouts often, some networks block the TCP
fallback DNS uses for larger responses (like an apex domain's full TXT
record set) - this is a network-level restriction, not something
Desisherlock can work around.

---

## NVD API key (optional but recommended)

CVE/CVSS lookups use the NVD REST API v2.0. Without a key you're limited
to 5 requests per 30 seconds; a free key (instant signup at
[nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key), no
cost) raises that to 50/30s. Set one with:

```bash
Desisherlock -configure
```

This also lets you set default thread count and timeout. Everything is
saved to `~/.desisherlock/config.json`.

---

## Where Desisherlock stores things

| Path | Contents |
|---|---|
| `~/.desisherlock/config.json` | Authorization-notice acknowledgement, NVD API key, default threads/timeout |
| `~/.desisherlock/reports/` | Saved reports from `-report` |

---

## Development

```bash
pip install --user -e .
pip install pytest
pytest
```

See [DISCLAIMER.md](DISCLAIMER.md) for the project's scope boundary before
proposing new modules.
