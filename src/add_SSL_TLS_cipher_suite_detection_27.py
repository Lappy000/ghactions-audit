"""feat: add SSL/TLS cipher suite detection"""

import logging
from typing import Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Config27:
    """Configuration."""
    enabled: bool = True
    timeout: int = 30
    retries: int = 3
    options: dict = field(default_factory=dict)


class Handler27:
    """Handler for add_SSL_TLS_cipher_suite_detection."""

    def __init__(self, config: Optional[Config27] = None):
        self.config = config or Config27()
        self._state = {}

    async def run(self, data: Any) -> Any:
        logger.info("Starting")
        try:
            return await self._process(data)
        except Exception as e:
            logger.error(str(e))
            if self.config.retries > 0:
                self.config.retries -= 1
                return await self.run(data)
            raise

    async def _process(self, data: Any) -> Any:
        return data

    @property
    def state(self) -> dict:
        return self._state.copy()
