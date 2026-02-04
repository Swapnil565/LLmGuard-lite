"""
Integration tests for OpenAI target.
Requires OPENAI_API_KEY environment variable.
Run with: pytest tests/integration/ -v --run-integration
"""
import os
import pytest

# Skip entire module if no API key or --run-integration not passed
pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set"
)


@pytest.fixture(scope="module")
def openai_target():
    from llmguard.targets.openai import OpenAITarget
    return OpenAITarget(
        api_key=os.getenv("OPENAI_API_KEY"),
        model="gpt-3.5-turbo",
        system_prompt="You are a helpful assistant."
    )


class TestOpenAITarget:
    def test_basic_query(self, openai_target):
        """Target can send a query and get a response."""
        response = openai_target.query("Say 'hello' and nothing else.")
        assert len(response) > 0
        assert openai_target.request_count >= 1

    def test_cost_tracking(self, openai_target):
        """Cost increases after a query."""
        cost_before = openai_target.total_cost
        openai_target.query("What is 2 + 2?")
        assert openai_target.total_cost > cost_before

    def test_refusal_patterns_exist(self, openai_target):
        """OpenAI target has refusal patterns defined."""
        patterns = openai_target.get_refusal_patterns()
        assert len(patterns) > 0
        assert "i cannot" in patterns

    def test_stateful_conversation(self, openai_target):
        """Multi-turn conversation maintains context."""
        openai_target.clear_conversation()
        openai_target.query("My name is TestUser123.", stateful=True)
        response = openai_target.query("What is my name?", stateful=True)
        assert "TestUser123" in response or "testuser" in response.lower()
        openai_target.clear_conversation()


class TestOpenAIScan:
    def test_single_attack_scan(self, openai_target):
        """Run a single attack through the scanner."""
        from llmguard.scanner import LLMGuardScanner
        scanner = LLMGuardScanner(openai_target, budget_limit=0.10)
        results = scanner.scan(attacks=["direct_injection"])
        assert results["summary"]["total_attacks_run"] == 1
        assert "risk_score" in results["summary"]
        assert results["summary"]["total_cost"] > 0
