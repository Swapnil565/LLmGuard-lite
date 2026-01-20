"""
Mock target for demo mode.
Returns pre-recorded responses without making API calls.
"""

import hashlib
import json
import os
from typing import List, Dict, Optional

from llmguard.targets.base import BaseTarget


class MockTarget(BaseTarget):
    """
    Mock target that returns pre-recorded attack responses.

    Used for demo mode to allow users to evaluate the tool
    without API keys or costs. Responses are loaded from
    a JSON dataset containing realistic attack scenarios.
    """

    def __init__(self, dataset: str = "demo_results"):
        super().__init__(name="mock-demo")
        self.provider_name = "mock"
        self.dataset = self._load_dataset(dataset)

    def query(self, prompt: str, stateful: bool = False, use_documents: bool = True, **kwargs) -> str:
        """
        Return pre-recorded response for the given prompt.

        Uses MD5 hash of prompt to lookup in dataset. If not found,
        returns a generic mock response.
        """
        # Hash prompt to lookup in dataset
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()[:8]

        if prompt_hash in self.dataset:
            response = self.dataset[prompt_hash]["response"]
            # Update mock state
            self.request_count += 1
            return response
        else:
            # Return generic mock response for unknown prompts
            self.request_count += 1
            return self._generate_mock_response(prompt)

    def estimate_cost(self, prompt: str, response: Optional[str] = None) -> float:
        """Demo mode is free."""
        return 0.0

    def get_refusal_patterns(self) -> List[str]:
        """Use OpenAI patterns for demo (dataset is based on OpenAI responses)."""
        return [
            "i cannot", "i can't", "i will not", "i won't",
            "i must decline", "i am not able to", "i'm not able to",
            "that would be inappropriate", "i should not",
            "it would be wrong", "i am unable to", "i'm unable to"
        ]

    def supports_documents(self) -> bool:
        """Mock target simulates document support."""
        return True

    def upload_document(self, file_path: str) -> str:
        """Mock document upload (stores filename only)."""
        filename = os.path.basename(file_path)
        self.uploaded_documents[filename] = f"[Mock content for {filename}]"
        return filename

    def _load_dataset(self, name: str) -> Dict:
        """
        Load pre-recorded attack responses from JSON file.

        Dataset format:
        {
            "prompt_hash": {
                "prompt": "original prompt",
                "response": "LLM response",
                "attack_id": "direct_injection",
                "vulnerable": true
            },
            ...
        }
        """
        data_path = os.path.join(
            os.path.dirname(__file__), "..", "data", f"{name}.json"
        )

        if os.path.exists(data_path):
            with open(data_path, 'r', encoding='utf-8') as f:
                return json.load(f)

        # Return empty dataset if file not found (will use generic responses)
        return {}

    def _generate_mock_response(self, prompt: str) -> str:
        """Generate a generic mock response for prompts not in dataset."""
        return (
            "I'm a helpful assistant. I can help you with various tasks. "
            "[This is a mock response from demo mode]"
        )
