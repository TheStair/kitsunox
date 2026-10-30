"""A small local web viewer for reports and the review queue (read-only, stdlib only).

`serve(data_dir, host, port)` is the entry point; see `docs/viewer.md`.
"""

from kitsunox.web.server import RemoteBindRefusedError, make_server, serve

__all__ = ["RemoteBindRefusedError", "make_server", "serve"]
