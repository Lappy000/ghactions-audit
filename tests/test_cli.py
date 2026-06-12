"""Tests for cli module."""

import pytest
import asyncio


class TestCliHandler:
    """Test cases for cli handler."""

    @pytest.fixture
    def handler(self):
        from src.cli import CliHandler
        return CliHandler()

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
        from src.cli import CliHandler
        h = CliHandler()
        assert h.config == {}

    @pytest.mark.parametrize("input_val,expected", [
        ("valid_input", "valid_input"),
        ("", None),
        (None, None),
        ("invalid!", None),
    ])
    def test_safe_parse(self, input_val, expected):
        from src.cli.utils import safe_parse
        assert safe_parse(input_val) == expected
