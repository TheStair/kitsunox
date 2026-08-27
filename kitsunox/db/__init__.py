"""Persistence layer.

Only this package imports SQLAlchemy. Everything else goes through
:class:`kitsunox.db.repo.Repository`, which is the single seam to swap SQLite for
Postgres later.
"""
