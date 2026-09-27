"""Keep the test suite independent of the local config.env.

src.config reads config.env when it is first imported. On a real monitor
that file holds real values (SMTP host, thresholds, tokens, NEVER_BAN), and
they leaked into tests that rely on defaults: a fresh setup_monitor.sh
install, which creates config.env from the example, failed
test_alerts::test_cooldown_suppresses_repeat. Pointing SECURENET_CONFIG at
an empty file before any test module imports src makes the suite see only
the built-in defaults, wherever it runs.
"""

import os

os.environ["SECURENET_CONFIG"] = os.devnull
