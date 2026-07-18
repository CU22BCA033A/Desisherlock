"""Shared helpers: color output, config persistence, severity classification."""
import json
import os
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _NoColor:
        def __getattr__(self, name):
            return ""

    Fore = _NoColor()
    Style = _NoColor()

CONFIG_DIR = Path.home() / ".desisherlock"
CONFIG_FILE = CONFIG_DIR / "config.json"
REPORTS_DIR = CONFIG_DIR / "reports"

DEFAULT_CONFIG = {
    "notice_ack": False,
    "nvd_api_key": None,
    "default_threads": 100,
    # 1.0s was too tight for real internet targets (as opposed to the local
    # test servers this was originally verified against) - a slow path or a
    # loaded target can easily exceed that, producing false "closed"
    # results for ports that are actually open. 3.0s is closer to what a
    # tool like nmap uses for TCP-connect scans by default.
    "default_timeout": 3.0,
}


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_config():
    ensure_config_dir()
    if not CONFIG_FILE.exists():
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(config):
    ensure_config_dir()
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def colorize(text, color):
    if not HAS_COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def info(text):
    return colorize(text, Fore.CYAN)


def success(text):
    return colorize(text, Fore.GREEN)


def warn(text):
    return colorize(text, Fore.YELLOW)


def error(text):
    return colorize(text, Fore.RED)


def bold(text):
    if not HAS_COLOR:
        return text
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


SEVERITY_THRESHOLDS = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)


def severity_from_score(score):
    """Map a CVSS base score (0-10) to a severity label."""
    if score is None:
        return "UNKNOWN"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "NONE"


def severity_color(label):
    colors = {
        "CRITICAL": Fore.MAGENTA,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN,
        "NONE": Fore.WHITE,
        "UNKNOWN": Fore.WHITE,
    }
    return colorize(label, colors.get(label, Fore.WHITE))
