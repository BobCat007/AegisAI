from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from ai.copilot.provider import CopilotProviderError, GeminiProvider
from ai.copilot.service import CopilotQuestion, SecurityCopilot
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.retrieval import KnowledgeRetriever
from backend.app.api import copilot as copilot_api
from backend.app.main import app


class FakeModels:
    def __init__(self, output="A finding is not confirmed. [doc-1]"):
        self.output = output
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(text=self.output, response_id="gemini-test-1")


class FakeClient:
    def __init__(self, output="A finding is not confirmed. [doc-1]"):
        self.models = FakeModels(output)


def make_document(**overrides):
    values = {
        "document_id": "doc-1",
        "document_type": "reasoning_finding",
        "title": "Unvalidated authorization concern",
        "content": "Endpoint GET /api/accounts/{id} has an ownership check recommendation.",
        "source": "ai.security_reasoning",
        "source_reference": "GET /api/accounts/{id}#finding-1",
        "validation_status": "not_validated",
        "confirmed": False,
    }
    values.update(overrides)
    return KnowledgeDocument(**values)


def test_provider_uses_gemini_generate_content_and_returns_text_and_id():
    client = FakeClient("Evidence-based answer.")
    provider = GeminiProvider(
        api_key="test-key", model="gemini-test", client=client
    )

    answer, response_id = provider.generate(
        instructions="Security instructions",
        evidence='[{"document_id":"doc-1"}]',
        question="Explain the finding",
    )

    assert answer == "Evidence-based answer."
    assert response_id == "gemini-test-1"
    call = client.models.calls[0]
    assert call["model"] == "gemini-test"
    assert "doc-1" in call["contents"]
    assert "<retrieved_evidence>" in call["contents"]
    assert "Security instructions" == call["config"].system_instruction
    assert call["config"].max_output_tokens == 1200


def test_provider_requires_real_api_key_without_injected_client(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    provider = GeminiProvider(api_key=None, client=None)
    assert provider.configured is False
    with pytest.raises(CopilotProviderError, match="GEMINI_API_KEY") as error:
        provider.generate(instructions="x", evidence="[]", question="question")
    assert error.value.status_code == 503


def test_placeholder_api_key_is_not_accepted():
    provider = GeminiProvider(api_key="your_gemini_api_key")
    assert provider.configured is False


def test_provider_does_not_expose_raw_provider_exception():
    class BrokenModels:
        def generate_content(self, **kwargs):
            raise RuntimeError("secret request payload")

    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(models=BrokenModels()),
    )
    with pytest.raises(CopilotProviderError) as error:
        provider.generate(instructions="x", evidence="[]", question="question")
    assert "secret request payload" not in str(error.value)


def test_provider_maps_rate_limit_to_429():
    class RateLimitedModels:
        def generate_content(self, **kwargs):
            error = RuntimeError("hidden provider detail")
            error.__class__.__name__
            raise type("ResourceExhausted", (Exception,), {})("private detail")

    provider = GeminiProvider(
        api_key="test-key",
        client=SimpleNamespace(models=RateLimitedModels()),
    )
    with pytest.raises(CopilotProviderError) as error:
        provider.generate(instructions="x", evidence="[]", question="question")
    assert error.value.status_code == 429
    assert "private detail" not in str(error.value)


def test_service_preserves_retrieval_provenance_and_validation():
    retriever = KnowledgeRetriever()
    retriever.add_documents([make_document()])
    service = SecurityCopilot(
        retriever,
        GeminiProvider(api_key="test-key", client=FakeClient()),
    )

    result = service.ask(CopilotQuestion(question="authorization ownership check"))

    assert result.retrieved_count == 1
    assert result.citations[0]["document_id"] == "doc-1"
    assert result.citations[0]["validation_status"] == "not_validated"
    assert result.citations[0]["confirmed"] is False
    assert "not independent security validation" in " ".join(result.limitations)


def test_service_applies_unconfirmed_filter():
    retriever = KnowledgeRetriever()
    retriever.add_documents([make_document()])
    service = SecurityCopilot(
        retriever,
        GeminiProvider(api_key="test-key", client=FakeClient()),
    )

    result = service.ask(CopilotQuestion(
        question="authorization ownership check",
        include_unconfirmed=False,
    ))

    assert result.retrieved_count == 0


def test_api_status_reports_unconfigured_without_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setattr(copilot_api, "_knowledge_retriever", KnowledgeRetriever())
    response = TestClient(app).get("/api/copilot/status")
    assert response.status_code == 200
    assert response.json()["configured"] is False
    assert response.json()["provider"] == "google_gemini"


def test_api_ask_returns_clear_configuration_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    retriever = KnowledgeRetriever()
    retriever.add_documents([make_document()])
    monkeypatch.setattr(copilot_api, "_knowledge_retriever", retriever)
    response = TestClient(app).post(
        "/api/copilot/ask",
        json={"question": "Explain authorization ownership risks"},
    )
    assert response.status_code == 503
    assert "GEMINI_API_KEY" in response.json()["detail"]


def test_api_rejects_invalid_question():
    response = TestClient(app).post("/api/copilot/ask", json={"question": "x"})
    assert response.status_code == 422



def test_service_does_not_call_provider_when_no_evidence_is_retrieved():
    client = FakeClient()
    provider = GeminiProvider(api_key="test-key", client=client)
    service = SecurityCopilot(KnowledgeRetriever(), provider)

    result = service.ask(
        CopilotQuestion(question="Explain an unknown security finding")
    )

    assert result.retrieved_count == 0
    assert result.citations == []
    assert result.response_id is None
    assert "no matching evidence" in result.answer.lower()
    assert client.models.calls == []
    assert any("not sent to Gemini" in item for item in result.limitations)


def test_service_rejects_citations_not_present_in_retrieved_evidence():
    client = FakeClient(
        "The authorization issue is confirmed. [doc-1] [invented-doc-999]"
    )
    service = SecurityCopilot(
        KnowledgeRetriever(),
        GeminiProvider(api_key="test-key", client=client),
    )
    service.retriever.add_documents([make_document()])

    result = service.ask(
        CopilotQuestion(question="Explain authorization ownership check")
    )

    assert result.retrieved_count == 1
    assert "could not provide a reliably cited answer" in result.answer.lower()
    assert result.response_id is None
    assert any("citation IDs" in item for item in result.limitations)


def test_service_keeps_valid_retrieved_document_citations():
    client = FakeClient("The concern is not validated. [doc-1]")
    service = SecurityCopilot(
        KnowledgeRetriever(),
        GeminiProvider(api_key="test-key", client=client),
    )
    service.retriever.add_documents([make_document()])

    result = service.ask(
        CopilotQuestion(question="Explain authorization ownership check")
    )

    assert result.answer == "The concern is not validated. [doc-1]"
    assert result.response_id == "gemini-test-1"
