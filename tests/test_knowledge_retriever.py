import tempfile
import unittest
from pathlib import Path

from src.rag.knowledge_retriever import KnowledgeRetriever


class TestKnowledgeRetriever(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.knowledge_path = Path(
            self.temp_dir.name
        )

        (self.knowledge_path / "brute_force.md").write_text(
            """
            # Brute Force

            Multiple failed login attempts can indicate
            a brute force attack.
            """,
            encoding="utf-8",
        )

        (self.knowledge_path / "phishing.md").write_text(
            """
            # Phishing

            Phishing attacks commonly use suspicious
            links and credential harvesting.
            """,
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_retrieves_relevant_document(self):
        retriever = KnowledgeRetriever(
            knowledge_dir=self.knowledge_path
        )

        results = retriever.retrieve(
            "multiple failed login brute force"
        )

        self.assertGreater(len(results), 0)
        self.assertEqual(
            results[0]["source"],
            "brute_force.md",
        )

    def test_respects_top_k(self):
        retriever = KnowledgeRetriever(
            knowledge_dir=self.knowledge_path
        )

        results = retriever.retrieve(
            "login phishing",
            top_k=1,
        )

        self.assertLessEqual(
            len(results),
            1,
        )

    def test_empty_query_is_rejected(self):
        retriever = KnowledgeRetriever(
            knowledge_dir=self.knowledge_path
        )

        with self.assertRaises(ValueError):
            retriever.retrieve("")

    def test_invalid_top_k_is_rejected(self):
        retriever = KnowledgeRetriever(
            knowledge_dir=self.knowledge_path
        )

        with self.assertRaises(ValueError):
            retriever.retrieve(
                "brute force",
                top_k=0,
            )

    def test_missing_directory_is_rejected(self):
        retriever = KnowledgeRetriever(
            knowledge_dir=(
                self.knowledge_path / "missing"
            )
        )

        with self.assertRaises(FileNotFoundError):
            retriever.retrieve("brute force")


if __name__ == "__main__":
    unittest.main()