from dataclasses import dataclass
from argon2 import PasswordHasher
from argon2.low_level import Type


@dataclass
class PasswordSecurity:
    # Strong-ish defaults for Argon2id; can be tuned per host
    time_cost: int = 3
    memory_cost: int = 65536  # 64 MiB
    parallelism: int = 2

    def __post_init__(self):
        self._ph = PasswordHasher(time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, type=Type.ID)

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, hashed: str, password: str) -> bool:
        try:
            return self._ph.verify(hashed, password)
        except Exception:
            return False
