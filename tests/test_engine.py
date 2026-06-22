"""Tests for engine module."""

import pytest
import asyncio


class TestEngineHandler:
    """Test cases for engine handler."""

    @pytest.fixture
    def handler(self):
        from src.engine import EngineHandler
        return EngineHandler()

    @pytest.mark.asyncio
    async def test_execute_returns_result(self, handler):
        result = await handler.execute("test")
        assert result is not None

    @pytest.mark.asyncio
    async def test_is_ready_after_execute(self, handler):
        assert not handler.is_ready
        await handler.execute("test")
        assert handler.is_ready

    def test_config_defaults(self):
        from src.engine import EngineHandler
        h = EngineHandler()
        assert h.config == {}

    @pytest.mark.parametrize("input_val,expected", [
        ("valid_input", "valid_input"),
        ("", None),
        (None, None),
        ("invalid!", None),
    ])
    def test_safe_parse(self, input_val, expected):
        from src.engine.utils import safe_parse
        assert safe_parse(input_val) == expected
