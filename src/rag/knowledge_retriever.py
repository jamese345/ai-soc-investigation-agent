from pathlib import Path
from typing import List


class KnowledgeRetriever:
    """Retrieves relevant cybersecurity knowledge from markdown files."""

    def __init__(self, knowledge_dir=None):
        self.knowledge_dir = Path(
            knowledge_dir or "data/knowledge"
        )

    def retrieve(self, query: str, top_k: int = 3) -> List[dict]:
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        if not self.knowledge_dir.exists():
            raise FileNotFoundError(
                f"Knowledge directory not found: {self.knowledge_dir}"
            )

        documents = self._load_documents()

        query_terms = self._tokenize(query)

        scored_documents = []

        for document in documents:
            score = self._score_document(
                query_terms,
                document["text"],
            )

            if score > 0:
                scored_documents.append(
                    {
                        "source": document["source"],
                        "content": document["text"],
                        "score": score,
                    }
                )

        scored_documents.sort(
            key=lambda item: item["score"],
            reverse=True,
        )

        return scored_documents[:top_k]

    def _load_documents(self):
        documents = []

        for path in sorted(self.knowledge_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8").strip()

            if not text:
                continue

            documents.append(
                {
                    "source": path.name,
                    "text": text,
                }
            )

        return documents

    @staticmethod
    def _tokenize(text: str):
        return {
            word.strip(".,:;!?()[]{}").lower()
            for word in text.split()
            if word.strip(".,:;!?()[]{}")
        }

    def _score_document(self, query_terms, document):
        document_terms = self._tokenize(document)

        return sum(
            1
            for term in query_terms
            if term in document_terms
        )