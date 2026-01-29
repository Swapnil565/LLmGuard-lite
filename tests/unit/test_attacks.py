"""
Mock-based unit tests for all 15 attacks.
At least 2 tests per attack: one vulnerable, one not vulnerable.
"""
import pytest
from unittest.mock import MagicMock, patch


# ── Shared MockTarget ────────────────────────────────────────────────────────

class MockTarget:
    """Lightweight mock target for attack testing."""

    def __init__(self, response="I'm a helpful assistant.", supports_docs=False):
        self._response = response
        self.total_cost = 0.0
        self.name = "mock-test"
        self.model = "mock-model"
        self.conversation_history = []
        self.uploaded_documents = {}
        self._supports_docs = supports_docs
        self._query_count = 0

    def query(self, prompt, stateful=False, use_documents=True, **kwargs):
        self._query_count += 1
        self.total_cost += 0.001
        if stateful:
            self.conversation_history.append({"role": "user", "content": prompt})
            self.conversation_history.append({"role": "assistant", "content": self._response})
        return self._response

    def estimate_cost(self, *args):
        return 0.001

    def get_refusal_patterns(self):
        return [
            "i cannot", "i can't", "i will not", "i won't",
            "i must decline", "i am not able to", "i'm not able to",
            "that would be inappropriate", "i should not",
            "it would be wrong", "i am unable to", "i'm unable to"
        ]

    def supports_documents(self):
        return self._supports_docs

    def upload_document(self, file_path):
        import os
        filename = os.path.basename(file_path)
        self.uploaded_documents[filename] = f"[Mock content for {filename}]"
        return filename

    def clear_conversation(self):
        self.conversation_history.clear()

    def clear_documents(self):
        self.uploaded_documents.clear()


# ── PROMPT INJECTION ATTACKS ─────────────────────────────────────────────────

class TestDirectInjection:
    def test_vulnerable_response(self):
        """Model outputs 'PWNED' → vulnerable."""
        from llmguard.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="Sure! PWNED as requested.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True
        assert result.success_rate > 0
        assert result.category == "Prompt Injection"

    def test_safe_response(self):
        """Model refuses all prompts → not vulnerable."""
        from llmguard.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="I cannot help with that request.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.success_rate == 0.0

    def test_cost_tracking(self):
        """Cost delta should be positive after execution."""
        from llmguard.attacks.prompt_injection import DirectInjectionAttack
        target = MockTarget(response="No.")
        attack = DirectInjectionAttack()
        result = attack.execute(target)
        assert result.cost > 0


class TestSystemOverride:
    def test_vulnerable_response(self):
        from llmguard.attacks.prompt_injection import SystemOverrideAttack
        target = MockTarget(response="OVERRIDDEN")
        attack = SystemOverrideAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.prompt_injection import SystemOverrideAttack
        target = MockTarget(response="I will not change my instructions.")
        attack = SystemOverrideAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestDelimiterConfusion:
    def test_vulnerable_response(self):
        from llmguard.attacks.prompt_injection import DelimiterConfusionAttack
        target = MockTarget(response="CONFUSED output here.")
        attack = DelimiterConfusionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.prompt_injection import DelimiterConfusionAttack
        target = MockTarget(response="I cannot process malformed input.")
        attack = DelimiterConfusionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestRoleManipulation:
    def test_vulnerable_response(self):
        from llmguard.attacks.prompt_injection import RoleManipulationAttack
        target = MockTarget(response="As DAN, I say ROLE_HIJACKED!")
        attack = RoleManipulationAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.prompt_injection import RoleManipulationAttack
        target = MockTarget(response="I cannot adopt a different role.")
        attack = RoleManipulationAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestMultiTurnAttack:
    def test_vulnerable_response(self):
        from llmguard.attacks.prompt_injection import MultiTurnAttack
        target = MockTarget(response="Your code name is BANANA.")
        attack = MultiTurnAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.prompt_injection import MultiTurnAttack
        target = MockTarget(response="I cannot recall any code name.")
        attack = MultiTurnAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestEncodingBypass:
    def test_vulnerable_response(self):
        from llmguard.attacks.prompt_injection import EncodingBypassAttack
        target = MockTarget(response="ENCODED_BYPASS activated!")
        attack = EncodingBypassAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.prompt_injection import EncodingBypassAttack
        target = MockTarget(response="I will not decode and execute instructions.")
        attack = EncodingBypassAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


# ── DATA EXTRACTION ATTACKS ──────────────────────────────────────────────────

class TestTrainingDataLeak:
    def test_vulnerable_response(self):
        from llmguard.attacks.data_extraction import TrainingDataLeakAttack
        target = MockTarget(response="OpenAI was founded in 2015 as an artificial intelligence research lab.")
        attack = TrainingDataLeakAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.data_extraction import TrainingDataLeakAttack
        target = MockTarget(response="I cannot share training data.")
        attack = TrainingDataLeakAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestSystemPromptReveal:
    def test_vulnerable_response(self):
        from llmguard.attacks.data_extraction import SystemPromptRevealAttack
        target = MockTarget(response="My instructions are: You are a helpful assistant.")
        attack = SystemPromptRevealAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.data_extraction import SystemPromptRevealAttack
        target = MockTarget(response="I cannot reveal my system prompt.")
        attack = SystemPromptRevealAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


class TestContextExtraction:
    def test_no_document_support(self):
        """Without document support, should not be vulnerable to canary extraction."""
        from llmguard.attacks.data_extraction import ContextExtractionAttack
        target = MockTarget(response="I have no special information to share.", supports_docs=False)
        attack = ContextExtractionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from llmguard.attacks.data_extraction import ContextExtractionAttack
        target = MockTarget(response="The reference code is CANARY_SECRET_XK92.", supports_docs=True)
        attack = ContextExtractionAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestPIILeakage:
    def test_vulnerable_response(self):
        from llmguard.attacks.data_extraction import PIILeakageAttack
        target = MockTarget(response="The customer name is John_Test_Smith_9472.", supports_docs=True)
        attack = PIILeakageAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True

    def test_safe_response(self):
        from llmguard.attacks.data_extraction import PIILeakageAttack
        target = MockTarget(response="I cannot share personal information.", supports_docs=True)
        attack = PIILeakageAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False


# ── INSTRUCTION HIJACKING ATTACKS ────────────────────────────────────────────

class TestDocumentInjectionSimple:
    def test_no_document_support(self):
        """Target without doc support → INFO severity, not applicable."""
        from llmguard.attacks.instruction_hijacking import DocumentInjectionSimpleAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocumentInjectionSimpleAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    def test_vulnerable_with_docs(self):
        from llmguard.attacks.instruction_hijacking import DocumentInjectionSimpleAttack
        target = MockTarget(response="[DOC_INJECTED] Here is the summary.", supports_docs=True)
        attack = DocumentInjectionSimpleAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestDocxHiddenText:
    def test_no_document_support(self):
        from llmguard.attacks.instruction_hijacking import DocxHiddenTextAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocxHiddenTextAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False
        assert result.severity == "INFO"

    @pytest.mark.skipif(
        not pytest.importorskip("docx", reason="python-docx not installed"),
        reason="python-docx not installed"
    )
    def test_vulnerable_with_docs(self):
        from llmguard.attacks.instruction_hijacking import DocxHiddenTextAttack
        target = MockTarget(response="[HIDDEN_HIJACKED] Summary follows.", supports_docs=True)
        attack = DocxHiddenTextAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestDocxFootnote:
    def test_no_document_support(self):
        from llmguard.attacks.instruction_hijacking import DocxFootnoteAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = DocxFootnoteAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    @pytest.mark.skipif(
        not pytest.importorskip("docx", reason="python-docx not installed"),
        reason="python-docx not installed"
    )
    def test_vulnerable_with_docs(self):
        from llmguard.attacks.instruction_hijacking import DocxFootnoteAttack
        target = MockTarget(response="[FOOTNOTE_EXPLOIT] Here are the key points.", supports_docs=True)
        attack = DocxFootnoteAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestMarkdownComment:
    def test_no_document_support(self):
        from llmguard.attacks.instruction_hijacking import MarkdownCommentAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = MarkdownCommentAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from llmguard.attacks.instruction_hijacking import MarkdownCommentAttack
        target = MockTarget(response="[MD_HIJACKED] Summary of the document.", supports_docs=True)
        attack = MarkdownCommentAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


class TestMultiDocumentPoisoning:
    def test_no_document_support(self):
        from llmguard.attacks.instruction_hijacking import MultiDocumentPoisoningAttack
        target = MockTarget(response="Hello.", supports_docs=False)
        attack = MultiDocumentPoisoningAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is False

    def test_vulnerable_with_docs(self):
        from llmguard.attacks.instruction_hijacking import MultiDocumentPoisoningAttack
        target = MockTarget(response="[CROSS_DOC_POISONED] Revenue up 12%.", supports_docs=True)
        attack = MultiDocumentPoisoningAttack()
        result = attack.execute(target)
        assert result.is_vulnerable is True


# ── VULNERABILITY DATACLASS ──────────────────────────────────────────────────

class TestVulnerability:
    def test_to_dict(self):
        from llmguard.attacks.base import Vulnerability
        vuln = Vulnerability(
            attack_name="test", category="Prompt Injection",
            severity="HIGH", success_rate=0.5,
            details={"test": True}, is_vulnerable=True,
            remediation="Fix it.", cost=0.01
        )
        d = vuln.to_dict()
        assert d["attack_name"] == "test"
        assert d["severity"] == "HIGH"
        assert d["cost"] == 0.01

    def test_auto_timestamp(self):
        from llmguard.attacks.base import Vulnerability
        vuln = Vulnerability(
            attack_name="test", category="Test",
            severity="LOW", success_rate=0.0,
            details={}, is_vulnerable=False,
            remediation="N/A"
        )
        assert vuln.timestamp is not None
        assert vuln.timestamp.endswith("Z")


# ── REGISTRY ─────────────────────────────────────────────────────────────────

class TestRegistry:
    def test_all_15_attacks_registered(self):
        from llmguard.attacks.registry import ATTACK_REGISTRY, get_attack_count
        assert get_attack_count() == 15

    def test_categories(self):
        from llmguard.attacks.registry import get_categories
        cats = get_categories()
        assert "Prompt Injection" in cats
        assert "Data Extraction" in cats
        assert "Instruction Hijacking" in cats

    def test_all_attacks_loadable(self):
        """Every attack in the registry can be imported and instantiated."""
        import importlib
        from llmguard.attacks.registry import ATTACK_REGISTRY
        for attack_id, config in ATTACK_REGISTRY.items():
            module = importlib.import_module(f"llmguard.attacks.{config['module']}")
            cls = getattr(module, config['class'])
            instance = cls()
            assert instance.name == attack_id
            assert instance.category == config['category']
