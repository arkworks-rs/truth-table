"""Page width and type for figures placed at full text width in the paper.

The width is the text width of the paper's full version (article class with
fullpage, 6.5 in), so a figure is included at `width=\\linewidth` without
scaling there; the IEEEtran version (7.0 in) enlarges it slightly. IEEE asks
for embedded, non-Type-3 fonts in a standard face at 8 pt or more: all text is
Liberation Sans (Arial's metrics) as TrueType at 8 pt, the smallest allowed,
which leaves the panels the most room.
"""

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib import font_manager

WIDTH_IN = 6.5
FONT = "Liberation Sans"
SIZE = 8


def apply(ink, muted_ink, base="default"):
    """Print-size type over the matplotlib style `base`."""
    for style in ("Regular", "Bold", "Italic", "BoldItalic"):
        path = f"/usr/share/fonts/liberation/LiberationSans-{style}.ttf"
        if Path(path).exists():
            font_manager.fontManager.addfont(path)
    plt.style.use(base)
    plt.rcParams.update(
        {
            "font.family": FONT,
            "font.size": SIZE,
            "axes.titlesize": SIZE,
            "axes.labelsize": SIZE,
            "xtick.labelsize": SIZE,
            "ytick.labelsize": SIZE,
            "legend.fontsize": SIZE,
            "axes.labelpad": 2,
            "xtick.major.pad": 2,
            "ytick.major.pad": 2,
            "text.color": ink,
            "axes.labelcolor": ink,
            "axes.edgecolor": muted_ink,
            "axes.linewidth": 0.6,
            "xtick.color": muted_ink,
            "ytick.color": muted_ink,
            "xtick.major.width": 0.6,
            "ytick.major.width": 0.6,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "pdf.fonttype": 42,
        }
    )
