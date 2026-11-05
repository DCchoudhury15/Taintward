"""Embedding requests and vector store writes are masked for the ``rag``
destination (an embedding can be turned back into text, and the store keeps
the text next to the vector). No API keys, no network.

Each test checks what actually left: the text the embedding provider got,
and what the store keeps. Spans must never hold a raw value or a vector.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
from types import SimpleNamespace

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taintward.sdk import instrumentation as instr
from taintward.sdk.integrations import Ward

SSN = "234-12-1234"
EMAIL = "alice@example.com"
DOC = f"Customer {EMAIL} has ssn {SSN}."


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except ModuleNotFoundError:
        return False


@pytest.fixture(autouse=True)
def _no_leftover_taint():
    """These calls run outside a run: their taint stays in the test
    thread's context. Drop it so later tests start clean."""
    yield
    instr._LOOSE_TAINT.set(None)


@pytest.fixture
def otel():
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("taintward"), exporter
    provider.shutdown()


@pytest.fixture
def ward(otel):
    return Ward({}, tracer=otel[0], llm_jurisdiction="us")


def rag_spans(exporter, op: str | None = None) -> list[dict]:
    spans = [dict(s.attributes or {}) | {"_name": s.name} for s in exporter.get_finished_spans()]
    assert SSN not in json.dumps(spans) and EMAIL not in json.dumps(spans)
    out = [a for a in spans if a.get("taintward.destination") == "rag"]
    if op == "embeddings":
        out = [a for a in out if a.get("gen_ai.operation.name") == "embeddings"]
    elif op == "add":
        out = [a for a in out if a.get("taintward.rag.operation") == "add"]
    return out


def no_raw(value) -> bool:
    text = json.dumps(value, default=str)
    return SSN not in text and EMAIL not in text


def test_redact_for_rag(ward):
    out = ward.redact_for_rag({"text": DOC, "source": "crm"})
    assert no_raw(out) and out["source"] == "crm"


# ---------------------------------------------------------------------------
# OpenAI SDK (mocked HTTP)
# ---------------------------------------------------------------------------


def _openai(bodies, *, is_async=False):
    import openai
    base = importlib.import_module("openai._base_client")
    httpx = getattr(base, "httpx2", None) or base.httpx

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        n = len(body["input"]) if isinstance(body["input"], list) else 1
        return httpx.Response(200, json={
            "object": "list", "model": "emb-test",
            "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]}
                     for i in range(n)],
            "usage": {"prompt_tokens": 7, "total_tokens": 7}})
    transport = httpx.MockTransport(handler)
    if is_async:
        return openai.AsyncOpenAI(api_key="t", base_url="http://fake.local/v1", max_retries=0,
                                  http_client=httpx.AsyncClient(transport=transport))
    return openai.OpenAI(api_key="t", base_url="http://fake.local/v1", max_retries=0,
                         http_client=httpx.Client(transport=transport))


@pytest.mark.skipif(not _has("openai"), reason="openai not installed")
class TestOpenAIEmbeddings:
    def test_input_is_masked(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_openai(bodies))
        r = client.embeddings.create(model="emb-test", input=[DOC, "plain text"])
        assert len(r.data) == 2
        assert no_raw(bodies[0]) and bodies[0]["input"][1] == "plain text"
        (a,) = rag_spans(otel[1], "embeddings")
        # rag is masked by redaction, not flagged as a violation; the span is tainted
        assert a["_name"] == "embeddings emb-test" and a["taintward.sensitive"] is True
        assert "taintward.violation" not in a
        assert json.loads(a["taintward.rag.output"]) == {"vectors": 2, "dimensions": 3}
        assert a["gen_ai.usage.input_tokens"] == 7

    def test_async_input_is_masked(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_openai(bodies, is_async=True))
        asyncio.run(client.embeddings.create(model="emb-test", input=DOC))
        assert no_raw(bodies[0])
        assert len(rag_spans(otel[1], "embeddings")) == 1

    def test_token_ids_are_sent_as_they_are(self, ward, otel):
        bodies = []
        client = ward.protect_openai(_openai(bodies))
        client.embeddings.create(model="emb-test", input=[[1, 2, 3]])
        assert bodies[0]["input"] == [[1, 2, 3]]


# ---------------------------------------------------------------------------
# LiteLLM (a stand-in module, so no network and no litellm needed)
# ---------------------------------------------------------------------------


def test_litellm_embedding_input_is_masked(ward, otel):
    pytest.importorskip("litellm")
    from taintward.sdk.integrations.litellm import protect_litellm
    sent = []

    def embedding(model, input=None, **kw):
        sent.append(input)
        return {"data": [{"embedding": [0.0] * 4} for _ in input]}

    async def aembedding(model, input=None, **kw):
        sent.append(input)
        return {"data": [{"embedding": [0.0] * 4} for _ in input]}
    mod = SimpleNamespace(embedding=embedding, aembedding=aembedding)
    protect_litellm(mod, ward=ward)
    mod.embedding("emb-test", input=[DOC])
    asyncio.run(mod.aembedding(model="emb-test", input=[DOC]))
    assert len(sent) == 2 and all(no_raw(s) for s in sent)
    spans = rag_spans(otel[1], "embeddings")
    assert len(spans) == 2
    assert json.loads(spans[0]["taintward.rag.output"]) == {"vectors": 1, "dimensions": 4}


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------


def _lc_embeddings(seen):
    from langchain_core.embeddings import DeterministicFakeEmbedding

    class Recording(DeterministicFakeEmbedding):
        def embed_documents(self, texts):
            seen.extend(texts)
            return super().embed_documents(texts)

        def embed_query(self, text):
            seen.append(text)
            return super().embed_query(text)
    return Recording(size=8)


@pytest.mark.skipif(not _has("langchain_core"), reason="langchain not installed")
class TestLangChain:
    def test_embeddings_are_masked(self, ward, otel):
        from langchain_core.embeddings import Embeddings
        seen = []
        emb = ward.protect_langchain_embeddings(_lc_embeddings(seen))
        assert isinstance(emb, Embeddings)
        assert len(emb.embed_documents([DOC])[0]) == 8
        emb.embed_query(f"what about {EMAIL}?")
        assert len(seen) == 2 and no_raw(seen)
        assert len(rag_spans(otel[1], "embeddings")) == 2

    def test_async_default_is_gated_once(self, ward, otel):
        seen = []
        emb = ward.protect_langchain_embeddings(_lc_embeddings(seen))
        # Embeddings.aembed_documents runs embed_documents in a thread
        asyncio.run(emb.aembed_documents([DOC]))
        assert no_raw(seen)
        assert len(rag_spans(otel[1], "embeddings")) == 1

    def test_vectorstore_keeps_masked_text(self, ward, otel):
        from langchain_core.documents import Document
        from langchain_core.vectorstores import InMemoryVectorStore
        seen = []
        emb = ward.protect_langchain_embeddings(_lc_embeddings(seen))
        store = ward.protect_langchain_vectorstore(InMemoryVectorStore(emb))
        assert isinstance(store, InMemoryVectorStore)
        doc = Document(page_content=DOC, metadata={"owner": EMAIL, "source": "crm"})
        store.add_documents([doc], ids=["d1"])
        store.add_texts(["another note", f"mail {EMAIL}"], metadatas=[{}, {"x": SSN}])
        kept = list(store.store.values())
        assert len(kept) == 3 and no_raw(kept)
        assert any(r["metadata"].get("source") == "crm" for r in kept)
        assert store.store["d1"]["text"] != DOC  # stored masked, id kept
        assert doc.page_content == DOC  # the caller's document is not changed
        hits = store.similarity_search(f"notes for {EMAIL}", k=1)
        assert hits and no_raw(seen)
        assert len(rag_spans(otel[1], "add")) == 2

    def test_store_with_its_own_add_texts(self, ward, otel):
        from langchain_core.documents import Document
        from langchain_core.vectorstores import VectorStore

        class TextsStore(VectorStore):
            """A store that implements add_texts itself (most community stores)."""

            def __init__(self):
                self.rows = []

            def add_texts(self, texts, metadatas=None, **kwargs):
                metadatas = metadatas or [{} for _ in texts]
                self.rows += list(zip(texts, metadatas))
                return [str(i) for i in range(len(self.rows))]

            def similarity_search(self, query, k=4, **kwargs):
                return [Document(page_content=t, metadata=m) for t, m in self.rows[:k]]

            @classmethod
            def from_texts(cls, texts, embedding, metadatas=None, **kwargs):
                raise NotImplementedError

        store = ward.protect_langchain_vectorstore(TextsStore())
        store.add_texts([DOC], metadatas=[{"owner": EMAIL}])
        store.add_documents([Document(page_content=f"mail {EMAIL}")])
        asyncio.run(store.aadd_texts([f"ssn {SSN}"]))
        assert len(store.rows) == 3 and no_raw(store.rows)
        assert len(rag_spans(otel[1], "add")) == 3

    def test_async_vectorstore_add(self, ward, otel):
        from langchain_core.documents import Document
        from langchain_core.vectorstores import InMemoryVectorStore
        store = ward.protect_langchain_vectorstore(InMemoryVectorStore(_lc_embeddings([])))
        asyncio.run(store.aadd_documents([Document(page_content=DOC)]))
        assert no_raw(list(store.store.values()))
        assert len(rag_spans(otel[1], "add")) == 1


# ---------------------------------------------------------------------------
# LlamaIndex
# ---------------------------------------------------------------------------


def _li_embedding(seen):
    from llama_index.core.embeddings import MockEmbedding

    class Recording(MockEmbedding):
        def _get_text_embeddings(self, texts):
            seen.extend(texts)
            return super()._get_text_embeddings(texts)

        def _get_text_embedding(self, text):
            seen.append(text)
            return super()._get_text_embedding(text)

        def _get_query_embedding(self, query):
            seen.append(query)
            return super()._get_query_embedding(query)

        async def _aget_query_embedding(self, query):
            seen.append(query)
            return await super()._aget_query_embedding(query)
    return Recording(embed_dim=4)


@pytest.mark.skipif(not _has("llama_index.core"), reason="llama-index not installed")
class TestLlamaIndex:
    def test_ingestion_pipeline_masks_nodes(self, ward, otel):
        from llama_index.core import Document
        from llama_index.core.ingestion import IngestionPipeline
        seen = []
        embed = ward.protect_llamaindex_embedding(_li_embedding(seen))
        doc = Document(text=DOC, metadata={"owner": EMAIL})
        nodes = IngestionPipeline(
            transformations=[ward.llamaindex_redact_nodes(), embed]).run(documents=[doc])
        assert len(nodes) == 1 and nodes[0].embedding is not None
        assert no_raw(nodes[0].get_content()) and no_raw(nodes[0].metadata)
        assert doc.text == DOC  # the input document is not changed
        assert seen and no_raw(seen)
        assert len(rag_spans(otel[1], "add")) == 1
        assert len(rag_spans(otel[1], "embeddings")) == 1

    def test_query_embedding_is_masked(self, ward, otel):
        seen = []
        embed = ward.protect_llamaindex_embedding(_li_embedding(seen))
        assert len(embed.get_query_embedding(f"orders of {EMAIL}")) == 4
        asyncio.run(embed.aget_query_embedding(f"orders of {EMAIL}"))
        assert len(seen) == 2 and no_raw(seen)
