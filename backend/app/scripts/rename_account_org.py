"""One-off admin script: renames a single account's organization name, matched by the login
email of a user belonging to it. Built for one explicitly-requested rename, not as a general
admin tool - both arguments are required, nothing is hardcoded or defaulted, so it can never
silently target the wrong account.

Aborts with no DB write at all unless EXACTLY one account matches the given login email.
Prints the before/after name on success.

Lives under app/ (not the repo-root scripts/) specifically so it ships inside the backend's
Docker image - see backend/Dockerfile's `COPY app ./app` - and is runnable from Render's
Shell tab, which starts in /app, the same WORKDIR docker-entrypoint.sh launches uvicorn from:

    python -m app.scripts.rename_account_org "<login-email>" "<new org name>"
"""

from __future__ import annotations

import sys

from app.db.models import Account, User
from app.db.session import SessionLocal


def rename_account_by_login_email(email: str, new_name: str) -> None:
    db = SessionLocal()
    try:
        matches = (
            db.query(Account)
            .join(User, User.account_id == Account.id)
            .filter(User.email == email)
            .all()
        )
        if len(matches) != 1:
            print(
                f"ABORTING: expected exactly 1 account for login email {email!r}, found "
                f"{len(matches)}. No change made.",
                file=sys.stderr,
            )
            sys.exit(1)

        account = matches[0]
        old_name = account.name
        account.name = new_name
        db.commit()
        print(f"Renamed account {account.id}: {old_name!r} -> {new_name!r}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            'Usage: python -m app.scripts.rename_account_org "<login-email>" "<new org name>"',
            file=sys.stderr,
        )
        sys.exit(2)
    rename_account_by_login_email(sys.argv[1], sys.argv[2])
