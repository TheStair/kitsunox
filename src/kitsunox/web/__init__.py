"""A small local web viewer for reports, the review queue and live evaluation results (stdlib
only; it writes nothing but the verdict log).

`serve(data_dir, host, port)` is the entry point; see `docs/viewer.md`.
"""

from kitsunox.web.server import RemoteBindRefusedError, make_server, serve

__all__ = ["RemoteBindRefusedError", "make_server", "serve"]
