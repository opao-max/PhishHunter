"""Tool abstraction and a safe, auditable execution registry."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout, as_completed
from typing import Any, Iterable

from ..models import ToolCall, ToolResult


class BaseTool(ABC):
    """A bounded investigation capability.

    Tools must be read-only, deterministic in mock mode, and must never fetch
    or execute content from an email.  Real integrations should subclass this
    and enforce their own network allow-lists.
    """

    name: str = ""
    description: str = ""
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    @abstractmethod
    def run(self, params: dict[str, Any]) -> ToolResult:
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        schema = self.input_schema or {}
        return {
            "name": self.name,
            "description": self.description,
            "required": list(schema.get("required", [])),
            "properties": dict(schema.get("properties", {})),
        }


class ToolRegistry:
    """Allow-listed tool registry with timeouts and audit-friendly results."""

    def __init__(self, tools: Iterable[BaseTool] | None = None) -> None:
        self._tools: dict[str, BaseTool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: BaseTool) -> None:
        if not getattr(tool, "name", ""):
            raise ValueError("Tool must define a non-empty name")
        if tool.name in self._tools:
            raise ValueError(f"Duplicate tool name: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> list[dict[str, Any]]:
        return [self._tools[name].describe() for name in self.names()]

    def execute(self, name: str, params: dict[str, Any] | None = None) -> ToolResult:
        started = time.perf_counter()
        params = dict(params or {})
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                tool=name,
                ok=False,
                error=f"Unknown tool: {name}",
                params=params,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        try:
            result = tool.run(params)
            if not isinstance(result, ToolResult):
                raise TypeError(
                    f"{name}.run() returned {type(result).__name__}, expected ToolResult"
                )
            result.params = params
            if result.latency_ms <= 0:
                result.latency_ms = (time.perf_counter() - started) * 1000
            return result
        except Exception as exc:  # noqa: BLE001 - one tool must not kill triage
            return ToolResult(
                tool=name,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                params=params,
                latency_ms=(time.perf_counter() - started) * 1000,
            )

    def execute_many(
        self,
        calls: list[ToolCall],
        *,
        timeout_s: float = 5.0,
        max_workers: int = 4,
    ) -> list[ToolResult]:
        """Execute calls concurrently with a bounded wall-clock budget.

        Python threads cannot be killed, so a misbehaving tool may keep
        running after this method returns.  The registry therefore stops
        *waiting* at the deadline and reports the call as timed out; real
        adapters must also enforce their own HTTP/socket timeouts.
        """
        if not calls:
            return []
        results: list[ToolResult | None] = [None] * len(calls)

        def run(index: int, call: ToolCall) -> tuple[int, ToolResult]:
            return index, self.execute(call.tool, call.params)

        workers = max(1, min(max_workers, len(calls)))
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {
            executor.submit(run, index, call): (index, call)
            for index, call in enumerate(calls)
        }
        try:
            for future in as_completed(futures, timeout=max(0.001, timeout_s)):
                index, call = futures[future]
                try:
                    _, result = future.result()
                    results[index] = result
                except Exception as exc:  # noqa: BLE001
                    results[index] = ToolResult(
                        tool=call.tool,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}",
                        params=dict(call.params),
                    )
        except FutureTimeout:
            pass
        finally:
            for future, (index, call) in futures.items():
                if results[index] is None:
                    future.cancel()
                    results[index] = ToolResult(
                        tool=call.tool,
                        ok=False,
                        error=f"Tool timed out after {timeout_s}s",
                        params=dict(call.params),
                        latency_ms=timeout_s * 1000,
                    )
            executor.shutdown(wait=False, cancel_futures=True)
        return [r for r in results if r is not None]