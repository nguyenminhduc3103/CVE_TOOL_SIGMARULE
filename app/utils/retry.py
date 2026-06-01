import asyncio
from typing import Callable


async def retry_async(fn: Callable, retries: int = 3, delay: float = 0.5):
    # TODO: implement backoff, jitter, and error filtering
    last = None
    for _ in range(retries):
        try:
            return await fn()
        except Exception as e:
            last = e
            await asyncio.sleep(delay)
    raise last
