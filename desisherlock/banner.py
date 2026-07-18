"""ASCII portrait (Sherlock deerstalker silhouette) + wordmark banner."""
from desisherlock import __version__

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False

# Deerstalker hat silhouette - the single most recognizable Sherlock Holmes
# element. Kept under 50 columns so it fits any terminal.
PORTRAIT = "\n".join([
    "",
    "              _.--~~~~--._",
    "           .-'    _..._    '-.",
    "         .'     .'     '.     '.",
    "        /      /  .-~~-.\\      \\",
    "       |      |  /      \\|      |",
    "       |      | |  o  o  ||     |",
    "       |      |  \\  ..  /|      |",
    "        \\      \\  '----' /      /",
    "         '.     '.__ __.'     .'",
    "           '-._    |    _.-'",
    "      .--------'-. | .-'--------.",
    "     /   .-------' '-------.     \\",
    "    |   /                    \\    |",
    "     \\_/                      \\_/",
    "",
])

FALLBACK_WORDMARK = r"""
 ____            _     _               _            _
|  _ \  ___  ___(_)___| |__   ___ _ __| | ___   ___| | __
| | | |/ _ \/ __| / __| '_ \ / _ \ '__| |/ _ \ / __| |/ /
| |_| |  __/\__ \ \__ \ | | |  __/ |  | | (_) | (__|   <
|____/ \___||___/_|___/_| |_|\___|_|  |_|\___/ \___|_|\_\
"""

TAGLINE = "Recon. Assess. Report. -- Elementary security tradecraft."
AUTH_NOTICE = (
    "For authorized security testing and educational use only. "
    "You are responsible for obtaining permission before scanning any target."
)


def get_wordmark():
    if HAS_PYFIGLET:
        try:
            fig = pyfiglet.Figlet(font="ansi_shadow", width=200)
            return fig.renderText("DESISHERLOCK")
        except Exception:
            try:
                return pyfiglet.figlet_format("DESISHERLOCK", font="standard", width=200)
            except Exception:
                return FALLBACK_WORDMARK
    return FALLBACK_WORDMARK


def get_banner(show_portrait=True):
    parts = []
    if show_portrait:
        parts.append(PORTRAIT)
    parts.append(get_wordmark())
    parts.append(TAGLINE)
    parts.append(f"v{__version__}")
    parts.append(AUTH_NOTICE)
    return "\n".join(parts)


if __name__ == "__main__":
    lines = PORTRAIT.splitlines()
    widths = [len(line) for line in lines]
    print(f"Portrait max width: {max(widths)} columns")
    print(PORTRAIT)
