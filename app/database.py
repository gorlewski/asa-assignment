from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str, owner_id: int) -> list:
    # Tenant isolation: results are constrained to the caller's own scans via
    # owner_id, so search cannot disclose other users' scans (BOLA/IDOR).
    # Parameterised query: the user input is passed as a bound parameter, never
    # interpolated into the SQL string, which prevents SQL injection. We also
    # escape the LIKE wildcards (%, _ and the escape char itself) so user input
    # is treated as a literal substring rather than a pattern.
    escaped = (
        query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    pattern = f"%{escaped}%"
    sql = text(
        "SELECT id, title, description, severity, status, cve_id, "
        "affected_component, owner_id, created_at FROM scan_results "
        "WHERE owner_id = :owner_id AND (title LIKE :pattern ESCAPE '\\' "
        "OR description LIKE :pattern ESCAPE '\\' "
        "OR cve_id LIKE :pattern ESCAPE '\\')"
    )
    result = db.execute(sql, {"pattern": pattern, "owner_id": owner_id})
    return [dict(row._mapping) for row in result]
