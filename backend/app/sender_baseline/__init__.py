"""Per-sender behavioral baselines for account-takeover detection.

- signals.py: what one email's headers say about how it was sent (pure).
- aggregation.py: folds a sender's prior observations into a SenderBaseline (pure).
- loader.py: the only DB code: loads a baseline, records an observation, and finds the
  account's own domains (for the lateral / internal-phishing case).

Consumed by app.indicators.account_takeover via SenderHistorySnapshot.sender_baseline.
"""
