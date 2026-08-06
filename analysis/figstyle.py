"""Publication-quality figure style shared by the figure scripts.
Serif font (matches the paper body text), subtle grid, thin strokes."""
import sys

import matplotlib

# Fonts the paper was typeset with, in preference order. DejaVu Serif is
# matplotlib's own fallback: it always resolves, but its glyphs are wider, so
# labels come out larger and can crowd each other compared with the published
# figures. The data is identical either way.
PAPER_SERIF = ["Liberation Serif", "Nimbus Roman", "Times New Roman"]


def _warn_if_font_missing():
    """Say so when the figures will not look like the paper's, instead of
    silently rendering them in a different typeface."""
    from matplotlib import font_manager
    have = {f.name for f in font_manager.fontManager.ttflist}
    if any(name in have for name in PAPER_SERIF):
        return
    print(
        "WARNING: none of %s is installed, so figures fall back to DejaVu "
        "Serif and will differ typographically from the published ones "
        "(every number is unaffected). Install one with:\n"
        "    sudo apt install fonts-liberation" % ", ".join(PAPER_SERIF),
        file=sys.stderr,
    )


def apply():
    import matplotlib.pyplot as plt
    _warn_if_font_missing()
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": PAPER_SERIF + ["DejaVu Serif"],
        "mathtext.fontset": "cm",
        "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9.5,
        "xtick.labelsize": 8, "ytick.labelsize": 8, "legend.fontsize": 7.6,
        "figure.dpi": 300, "savefig.dpi": 300,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.linewidth": 0.6, "axes.axisbelow": True,
        "axes.titlepad": 4.0, "axes.labelpad": 2.5,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "xtick.major.size": 2.8, "ytick.major.size": 2.8,
        "lines.linewidth": 1.6,
        "legend.frameon": False, "legend.handlelength": 1.6,
    })


def grid(ax, axis="y"):
    """Subtle grid behind the data, on the value axis."""
    ax.set_axisbelow(True)
    ax.grid(axis=axis, color="#d8d8d8", linewidth=0.5, zorder=0)
