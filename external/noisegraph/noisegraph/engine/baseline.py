from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import math

def timebucket_index(ts_iso: str, bucket_minutes: int) -> int:
    dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).astimezone(timezone.utc)
    minutes = dt.hour * 60 + dt.minute
    return minutes // bucket_minutes

@dataclass
class BaselineUpdate:
    ewma: float
    q50: float
    q90: float
    q99: float

def update_baseline(prev: dict | None, observed_rate: float, alpha: float) -> BaselineUpdate:
    if prev is None:
        ewma = observed_rate
    else:
        ewma = (alpha * observed_rate) + ((1 - alpha) * float(prev["ewma"]))
    # Use Poisson quantiles for count-based baselines to reduce false positives at low rates.
    q50 = poisson_quantile(0.50, ewma)
    q90 = poisson_quantile(0.90, ewma)
    q99 = poisson_quantile(0.99, ewma)
    return BaselineUpdate(ewma=ewma, q50=q50, q90=q90, q99=q99)


def adaptive_alpha(
    base_alpha: float, prev_ewma: float | None, observed: float, min_alpha: float, max_alpha: float
) -> float:
    if prev_ewma is None:
        return base_alpha
    denom = max(prev_ewma, 1.0)
    ratio = abs(observed - prev_ewma) / denom
    a = base_alpha * (1.0 + ratio)
    return max(min_alpha, min(max_alpha, a))


def poisson_quantile(p: float, lam: float) -> float:
    if lam <= 0:
        return 0.0
    # Sum CDF until reaching target probability.
    # This is fast for typical low rates seen in log templates.
    k = 0
    pmf = math.exp(-lam)
    cdf = pmf
    while cdf < p:
        k += 1
        pmf *= lam / k
        cdf += pmf
        if k > 10_000:
            break
    return float(k)
