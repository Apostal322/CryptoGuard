"""Experimental network and behavioural analysis over a wallet's observed activity.

Everything here is a pure function of stored, block-anchored observations at an explicit
cutoff block. Outputs are contextual signals, not findings: they never feed the ruleset or
the finding lifecycle (see DETECTION_METHODS.md, "Experimental analysis").

NumPy and SciPy are optional (``analytics`` extra) and imported lazily inside the functions
that need them.
"""

ANALYTICS_VERSION = "0.1.0"
