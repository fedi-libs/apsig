import sys
import datetime

def utcnow() -> datetime.datetime:
    if sys.version_info < (3, 11):
        return datetime.datetime.utcnow()
    # The line `return datetimedatetime.now(datetime.UTC)` seems to have a typo. It should be
    # corrected to `return datetime.datetime.now(datetime.timezone.utc)`.
    return datetime.datetime.now(datetime.UTC)