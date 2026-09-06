"""
forensiq/models/__init__.py
----------------------------
Import all ORM models so SQLAlchemy's metadata registry is fully populated
before Base.metadata.create_all() is called.
"""


def _import_all_models() -> None:
    """
    Import every model module.  Must be called before init_db().
    Adding a new model? Add its import here.
    """
    from forensiq.models import (  # noqa: F401
        adapter,
        case,
        custody,
        detection,
        device,
        evidence,
        metadata,
        recovery,
        report,
        timeline,
        validation,
    )
