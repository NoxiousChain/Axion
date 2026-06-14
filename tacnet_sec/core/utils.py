
import hashlib, time, math
from collections import Counter
from typing import List

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def now_ts() -> float:
    return time.time()

def shannon_entropy(values: List[str]) -> float:
    if not values:
        return 0.0
    c = Counter(values)
    total = sum(c.values())
    ent = 0.0
    for v in c.values():
        p = v / total
        ent -= p * math.log(p, 2)
    return ent
