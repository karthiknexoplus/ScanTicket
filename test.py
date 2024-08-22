# test_datetime.py
from datetime import datetime, timedelta

def test_datetime():
    try:
        now = datetime.now()
        print(f"Current datetime: {now}")
        yesterday = now - timedelta(days=1)
        print(f"Yesterday: {yesterday}")
    except AttributeError as e:
        print(f"Error: {e}")

test_datetime()
