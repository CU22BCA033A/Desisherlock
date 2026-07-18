"""argparse-based CLI + interactive REPL, dispatching to the recon modules."""
import argparse
import json
import shlex
import sys

try:
    import readline  # noqa: F401  (importing enables input() line history/editing)
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

from desisherlock import __version__
from desisherlock import banner as banner_mod
from desisherlock import utils
from desisherlock.modules import (
    dns_recon,
    hashid,
    portscan,
    report,
    ssl_tls,
    vuln,
    webrecon,
    whois_lookup,
)

NETWORK_COMMANDS = {
    "scan", "port_scan", "vuln_check", "cvss", "web", "ssl", "dns", "whois", "audit",
}

EXIT_WORDS = {"close", "exit", "quit", "bye", "q"}
CONVENIENCE_WORDS = {"help", "clear", "version", "banner"}

GOODBYE = "The game is over, for now. Farewell."


def build_parser():
    parser = argparse.ArgumentParser(
        prog="Desisherlock",
        add_help=False,
        allow_abbrev=False,
        description="Recon, vulnerability-assessment, and reporting toolkit.",
    )

    parser.add_argument("target", nargs="?", default=None, help="Target (IP/host/domain/URL)")

    parser.add_argument("-S", "--scan", nargs="?", const="__use_target__", default=None,
                         metavar="target", help="Liveness check + top-ports scan + banner grab")
    parser.add_argument("-port", "--port-scan", nargs="?", const="__use_target__", default=None,
                         metavar="target", help="Full port scan")
    parser.add_argument("-p", "--ports", default="top", help="Port spec: top, 1-65535, 22,80,443, or mixed")
    parser.add_argument("--threads", type=int, default=None, help="Thread count for port scanning")

    parser.add_argument("-Vc", "--vuln-check", action="store_true",
                         help="Cross-check found banners against CVEs, or run standalone")
    parser.add_argument("--product", default=None, help="Product name for standalone -Vc")
    parser.add_argument("--pversion", default=None, help="Product version for standalone -Vc")

    parser.add_argument("-CVSS", dest="cvss", default=None, metavar="CVE-ID|keyword",
                         help="Direct NVD CVE/CVSS lookup")

    parser.add_argument("-web", dest="web", nargs="?", const="__use_target__", default=None,
                         metavar="url", help="Header analysis + exposed-path check")

    parser.add_argument("-ssl", dest="ssl", nargs="?", const="__use_target__", default=None,
                         metavar="host[:port]", help="Certificate + cipher inspection")

    parser.add_argument("-dns", dest="dns", nargs="?", const="__use_target__", default=None,
                         metavar="domain", help="DNS record enumeration + subdomain brute force")
    parser.add_argument("--wordlist", default=None, help="Override the bundled subdomain wordlist")

    parser.add_argument("-hash", dest="hash_value", default=None, metavar="string",
                         help="Hash format identification only")

    parser.add_argument("-whois", dest="whois_domain", nargs="?", const="__use_target__", default=None,
                         metavar="domain", help="WHOIS registration lookup")

    parser.add_argument("-audit", dest="audit", nargs="?", const="__use_target__", default=None,
                         metavar="target", help="Run scan+ssl+dns+web+whois against one target and auto-save a report")

    parser.add_argument("-report", dest="report_fmt", nargs="?", const="md", default=None,
                         choices=["md", "html", "json", "csv"], metavar="md|html|json|csv",
                         help="Render the session's accumulated findings")

    parser.add_argument("-o", "--output", default=None, metavar="file",
                         help="Dump the current command's raw result as JSON")

    parser.add_argument("-configure", dest="configure", action="store_true",
                         help="Interactively set NVD API key + defaults")
    parser.add_argument("-update", dest="update", action="store_true", help="Check for/apply updates")
    parser.add_argument("-list", dest="show_help", action="store_true", help="Show help")
    parser.add_argument("-h", "--help", dest="show_help", action="store_true", help="Show help")
    parser.add_argument("--version", action="store_true", help="Show version")

    parser.add_argument("-t", "--target", dest="target_flag", default=None,
                         help="Explicit target (alternative to positional)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the authorization notice")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")

    return parser


def resolve_target(args, inline_value):
    if inline_value not in (None, "__use_target__"):
        return inline_value
    if args.target_flag:
        return args.target_flag
    if args.target:
        return args.target
    return None


def show_authorization_notice(skip=False):
    config = utils.load_config()
    if config.get("notice_ack"):
        return
    if not skip:
        print(utils.bold("=" * 60))
        print(utils.warn(banner_mod.AUTH_NOTICE))
        print(utils.bold("=" * 60))
        try:
            input("Press Enter to continue... ")
        except (EOFError, KeyboardInterrupt):
            print()
    config["notice_ack"] = True
    utils.save_config(config)


def any_network_command_requested(args):
    if args.scan is not None:
        return True
    if getattr(args, "port_scan", None) is not None:
        return True
    if args.vuln_check or args.cvss:
        return True
    if args.web is not None:
        return True
    if args.ssl is not None:
        return True
    if args.dns is not None:
        return True
    if args.whois_domain is not None:
        return True
    if getattr(args, "audit", None) is not None:
        return True
    return False


def _print_json(data):
    print(json.dumps(data, indent=2, default=str))


def _maybe_write_output(args, data):
    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(utils.info(f"Raw result written to {args.output}"))


def run_audit(target, config, session, timeout, threads):
    """-audit: run scan+ssl+dns+web+whois against one target back-to-back
    and auto-save a Markdown report, for a single-command full recon pass."""
    host, _, port_str = target.partition(":")
    ssl_port = int(port_str) if port_str.isdigit() else 443

    print(utils.bold(f"=== Full audit: {host} ==="))

    print(utils.info("[1/5] Port scan (-S)..."))
    scan_result = portscan.scan(host, timeout=timeout, threads=threads)
    session.record("scan", scan_result)
    _print_json(scan_result)

    print(utils.info(f"[2/5] TLS inspection (-ssl {host}:{ssl_port})..."))
    ssl_result = ssl_tls.inspect(host, port=ssl_port)
    session.record("ssl", ssl_result)
    _print_json(ssl_result)

    print(utils.info("[3/5] DNS recon (-dns)..."))
    dns_result = dns_recon.recon(host)
    session.record("dns", dns_result)
    _print_json(dns_result)

    print(utils.info("[4/5] Web recon (-web)..."))
    web_result = webrecon.recon(host, timeout=15)
    session.record("web", web_result)
    _print_json(web_result)

    print(utils.info("[5/5] WHOIS lookup (-whois)..."))
    whois_result = whois_lookup.lookup(host)
    session.record("whois", whois_result)
    _print_json(whois_result)

    report_path = report.save(session, fmt="md")
    print(utils.success(f"[+] Full audit complete. Report saved to {report_path}"))


def dispatch(args, session):
    config = utils.load_config()
    threads = args.threads or config.get("default_threads", 100)
    timeout = config.get("default_timeout", 1.0)
    ran_anything = False
    last_result = None

    if args.version:
        print(f"Desisherlock v{__version__}")
        return

    if args.show_help:
        print_help_text()
        return

    if args.configure:
        run_configure_wizard()
        return

    if args.update:
        print(utils.info("You're on the latest version available via this install method."))
        return

    if any_network_command_requested(args):
        show_authorization_notice(skip=args.yes)

    if args.scan is not None:
        target = resolve_target(args, args.scan)
        if not target:
            print(utils.error("No target specified for -S/--scan"))
        else:
            print(utils.info(f"[*] Scanning {target}..."))
            result = portscan.scan(target, timeout=timeout, threads=threads)
            session.record("scan", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if getattr(args, "port_scan", None) is not None:
        target = resolve_target(args, args.port_scan)
        if not target:
            print(utils.error("No target specified for -port/--port-scan"))
        else:
            print(utils.info(f"[*] Port scanning {target} ({args.ports})..."))
            try:
                result = portscan.port_scan(target, port_spec=args.ports, timeout=timeout, threads=threads)
            except ValueError as e:
                result = {"target": target, "error": str(e)}
            session.record("port_scan", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if args.vuln_check:
        if args.product:
            keyword = f"{args.product} {args.pversion}".strip() if args.pversion else args.product
            print(utils.info(f"[*] Vulnerability check for '{keyword}'..."))
            result = vuln.lookup(keyword, api_key=config.get("nvd_api_key"))
            session.record("vuln_check", result)
            _print_json(result)
            last_result = result
        elif last_result and last_result.get("open_ports"):
            print(utils.info("[*] Cross-checking discovered banners against CVEs..."))
            checks = []
            for port_entry in last_result["open_ports"]:
                banner_text = port_entry.get("banner")
                if banner_text and "use -ssl" not in banner_text:
                    checks.append(vuln.lookup(banner_text, api_key=config.get("nvd_api_key")))
            session.record("vuln_check", checks)
            _print_json(checks)
            last_result = checks
        else:
            target = resolve_target(args, None)
            if target:
                print(utils.info(f"[*] Vulnerability check for keyword '{target}'..."))
                result = vuln.lookup(target, api_key=config.get("nvd_api_key"))
                session.record("vuln_check", result)
                _print_json(result)
                last_result = result
            else:
                print(utils.error("No product/keyword/target given for -Vc"))
        ran_anything = True

    if args.cvss:
        print(utils.info(f"[*] NVD lookup for '{args.cvss}'..."))
        result = vuln.lookup(args.cvss, api_key=config.get("nvd_api_key"))
        session.record("cvss", result)
        _print_json(result)
        last_result = result
        ran_anything = True

    if args.web is not None:
        target = resolve_target(args, args.web)
        if not target:
            print(utils.error("No URL specified for -web"))
        else:
            print(utils.info(f"[*] Web recon on {target}..."))
            result = webrecon.recon(target, timeout=15)
            session.record("web", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if args.ssl is not None:
        target = resolve_target(args, args.ssl)
        if not target:
            print(utils.error("No host specified for -ssl"))
        else:
            host, _, port_str = target.partition(":")
            port = int(port_str) if port_str else 443
            print(utils.info(f"[*] TLS inspection of {host}:{port}..."))
            result = ssl_tls.inspect(host, port=port)
            session.record("ssl", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if args.dns is not None:
        target = resolve_target(args, args.dns)
        if not target:
            print(utils.error("No domain specified for -dns"))
        else:
            print(utils.info(f"[*] DNS recon on {target}..."))
            result = dns_recon.recon(target, wordlist_path=args.wordlist)
            session.record("dns", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if args.hash_value is not None:
        result = hashid.identify_result(args.hash_value)
        session.record("hash", result)
        _print_json(result)
        last_result = result
        ran_anything = True

    if args.whois_domain is not None:
        target = resolve_target(args, args.whois_domain)
        if not target:
            print(utils.error("No domain specified for -whois"))
        else:
            print(utils.info(f"[*] WHOIS lookup for {target}..."))
            result = whois_lookup.lookup(target)
            session.record("whois", result)
            _print_json(result)
            last_result = result
        ran_anything = True

    if getattr(args, "audit", None) is not None:
        target = resolve_target(args, args.audit)
        if not target:
            print(utils.error("No target specified for -audit"))
        else:
            run_audit(target, config, session, timeout, threads)
        ran_anything = True

    if args.report_fmt is not None:
        path = report.save(session, fmt=args.report_fmt)
        print(utils.success(f"[+] Report saved to {path}"))
        ran_anything = True

    if last_result is not None:
        _maybe_write_output(args, last_result)

    if not ran_anything:
        print_help_text()


def run_configure_wizard():
    config = utils.load_config()
    print(utils.bold("Desisherlock configuration"))
    try:
        api_key = input(f"NVD API key [{config.get('nvd_api_key') or 'none'}]: ").strip()
        threads = input(f"Default threads [{config.get('default_threads')}]: ").strip()
        timeout = input(f"Default timeout (seconds) [{config.get('default_timeout')}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if api_key:
        config["nvd_api_key"] = api_key
    if threads:
        try:
            config["default_threads"] = int(threads)
        except ValueError:
            print(utils.warn("Ignoring invalid thread count"))
    if timeout:
        try:
            config["default_timeout"] = float(timeout)
        except ValueError:
            print(utils.warn("Ignoring invalid timeout"))

    utils.save_config(config)
    print(utils.success("Configuration saved."))


def print_help_text():
    parser = build_parser()
    print(parser.format_help())


def print_banner(show_portrait=True):
    print(banner_mod.get_banner(show_portrait=show_portrait))


def _history_file():
    utils.ensure_config_dir()
    return str(utils.CONFIG_DIR / "history")


def _load_history():
    if not HAS_READLINE:
        return
    readline.set_history_length(1000)
    try:
        readline.read_history_file(_history_file())
    except (FileNotFoundError, OSError):
        pass


def _save_history():
    if not HAS_READLINE:
        return
    try:
        readline.write_history_file(_history_file())
    except OSError:
        pass


def repl(show_banner=True):
    session = report.Session()
    parser = build_parser()
    _load_history()
    if show_banner:
        print_banner()
    print("Type 'help' for commands, 'close' (or exit/quit/bye/q) to leave.")
    print("Use the up/down arrow keys to recall previous commands.")

    while True:
        try:
            line = input("Desisherlock ~$ ")
        except (EOFError, KeyboardInterrupt):
            print()
            print(utils.info(GOODBYE))
            _save_history()
            break

        line = line.strip()
        if not line:
            continue

        try:
            tokens = shlex.split(line)
        except ValueError as e:
            print(utils.error(f"Could not parse input: {e}"))
            continue

        if not tokens:
            continue

        # Tolerate an optional leading literal "Desisherlock" token.
        if tokens[0].lower() == "desisherlock":
            tokens = tokens[1:]

        if not tokens:
            continue

        lowered = " ".join(t.lower() for t in tokens)

        if lowered in EXIT_WORDS:
            print(utils.info(GOODBYE))
            _save_history()
            break

        if len(tokens) == 1 and tokens[0].lower() in CONVENIENCE_WORDS:
            word = tokens[0].lower()
            if word == "help":
                print_help_text()
            elif word == "clear":
                print("\033c", end="")
            elif word == "version":
                print(f"Desisherlock v{__version__}")
            elif word == "banner":
                print_banner()
            continue

        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            # argparse calls sys.exit() on any parse error - catch it so one
            # typo doesn't kill the whole REPL session.
            continue

        try:
            dispatch(args, session)
        except Exception as e:
            print(utils.error(f"Error: {e}"))


def _requests_a_command(args):
    """True if this invocation asked for any actual command, not just
    plumbing flags like --no-banner/-y/-t that only make sense alongside one."""
    return any([
        args.target, args.scan is not None, args.port_scan is not None,
        args.vuln_check, args.cvss, args.web is not None, args.ssl is not None,
        args.dns is not None, args.hash_value is not None, args.whois_domain is not None,
        args.audit is not None, args.report_fmt is not None, args.configure, args.update,
        args.show_help, args.version,
    ])


def main():
    argv = sys.argv[1:]
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        raise

    if not _requests_a_command(args):
        repl(show_banner=not args.no_banner)
        return

    session = report.Session()
    dispatch(args, session)


if __name__ == "__main__":
    main()
