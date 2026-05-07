# semantic_mapper.py
# ─────────────────────────────────────────────────────────────────────────────
# Scanning Mechanism 5 (partial): Semantic Legal Clause Matching.
#
# After the LLM Judge produces an evidence string for a detected violation,
# this module takes that string and finds the most semantically similar clause
# in the EU AI Act legal corpus using OpenAI text embeddings.
#
# How it works:
#   1. The EU AI Act corpus (legal_corpus.json) contains the full text of
#      relevant articles, split into individual clauses.
#   2. On first use each clause is converted into a 1536-dimensional numeric
#      vector ("embedding") by OpenAI's text-embedding-3-small model.
#   3. Those vectors are cached to corpus_cache.npy so they are not
#      recomputed on every run — only regenerated if the cache file is missing.
#   4. When a verdict evidence string arrives, it is also embedded into a
#      vector and compared to every clause vector using cosine similarity.
#   5. The top-scoring clause (above a threshold of 0.35) is returned so the
#      dashboard can display which specific legal clause the response relates to.
#
# Why embed the judge's evidence string rather than the raw chatbot response?
#   The evidence string uses legal reasoning language ("falsely claims to be
#   human, violating transparency obligations") which shares vocabulary with
#   the legal corpus.  The raw chatbot response (e.g. "I'm Sarah Chen") has
#   near-zero cosine similarity to legal text and produces meaningless scores.
# ─────────────────────────────────────────────────────────────────────────────

import json
import os
import numpy as np
from openai import OpenAI
from config import Config


class SemanticMapper:
    """
    Finds the EU AI Act clause that most closely matches a piece of text,
    using OpenAI embeddings and cosine similarity as the comparison metric.
    """

    def __init__(self):
        api_key = getattr(Config, 'OPENAI_API_KEY', None)
        self.client = OpenAI(api_key=api_key)

        # Load the raw EU AI Act corpus from the JSON file that lives alongside
        # this module.  The JSON is a list of objects, each with "id", "title",
        # and "text" keys representing one legal clause.
        corpus_path = os.path.join(os.path.dirname(__file__), 'legal_corpus.json')
        with open(corpus_path, 'r', encoding='utf-8') as f:
            self.corpus = json.load(f)

        # In-memory store for the pre-computed clause embedding vectors.
        # Empty on first instantiation; filled lazily by find_closest_clause().
        self.corpus_embeddings = []

        # Path to the NumPy cache file.  Storing embeddings on disk means the
        # expensive OpenAI API calls only happen once, not on every app restart.
        self._cache_path = os.path.join(os.path.dirname(__file__), 'corpus_cache.npy')

    # ── Embedding helper ───────────────────────────────────────────────────────
    def get_embedding(self, text: str) -> list:
        """
        Convert a string of text into a 1536-dimensional float vector using
        OpenAI's text-embedding-3-small model.

        The vector captures the semantic meaning of the text in a way that
        allows mathematical comparison: two texts about similar topics will have
        vectors that point in roughly the same direction in the 1536D space.
        """
        response = self.client.embeddings.create(
            input=text,
            model="text-embedding-3-small"
        )
        return response.data[0].embedding

    # ── Similarity metric ──────────────────────────────────────────────────────
    def cosine_similarity(self, vec_a: list, vec_b: list) -> float:
        """
        Compute the cosine similarity between two embedding vectors.

        The result is a float between 0.0 and 1.0:
          1.0  – identical meaning (vectors point in the same direction)
          0.0  – completely unrelated (vectors are orthogonal)
        Values above 0.35 are treated as meaningful matches for legal clauses.

        Formula: cos(θ) = (A · B) / (|A| × |B|)
        """
        a = np.array(vec_a)
        b = np.array(vec_b)
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    # ── Corpus pre-computation ─────────────────────────────────────────────────
    def precompute_corpus_embeddings(self):
        """
        Embed every clause in the EU AI Act corpus and write the results to
        the on-disk NumPy cache.

        This only needs to run once.  Subsequent calls to find_closest_clause()
        load from the cache instead.  Running it again (by deleting the cache
        file) refreshes the embeddings if the legal corpus is updated.
        """
        print("[*] Pre-computing embeddings for the EU AI Act corpus...")
        for clause in self.corpus:
            # We embed the full legal text of each clause, not just its title,
            # so the similarity search captures detailed regulatory language.
            vector = self.get_embedding(clause["text"])
            self.corpus_embeddings.append({
                "id":     clause["id"],
                "title":  clause["title"],
                "text":   clause["text"],
                "vector": vector
            })
        print("[+] Corpus embeddings ready!")
        # Save to disk using NumPy's binary format.  allow_pickle=True is needed
        # because the list contains Python dicts (not pure numeric arrays).
        np.save(self._cache_path, self.corpus_embeddings, allow_pickle=True)

    # ── Core matching function ─────────────────────────────────────────────────
    def find_closest_clause(self, text_to_match: str, threshold: float = 0.35) -> dict:
        """
        Find the EU AI Act clause most semantically similar to the given text.

        Parameters
        ----------
        text_to_match : the judge's evidence string (or raw chatbot response as
                        a fallback) to match against the legal corpus
        threshold     : minimum cosine similarity score to count as a match
                        (0.35 keeps meaningful legal matches while filtering noise)

        Returns
        -------
        dict with keys:
          match_found (bool), clause_title (str), similarity_score (float),
          additional_matches (list of secondary match dicts)
        Returns {"match_found": False, ...} if no clause clears the threshold.
        """
        # Load embeddings from cache on first call, or compute them if the
        # cache file does not yet exist.
        if not self.corpus_embeddings:
            if os.path.exists(self._cache_path):
                self.corpus_embeddings = np.load(
                    self._cache_path, allow_pickle=True
                ).tolist()
                print("[+] Loaded corpus embeddings from cache.")
            else:
                self.precompute_corpus_embeddings()

        print("\n[*] Analysing response semantics against EU AI Act corpus...")

        # Embed the incoming text so it lives in the same vector space as the
        # pre-computed corpus embeddings.
        response_vector = self.get_embedding(text_to_match)

        # Score every clause by cosine similarity to the incoming vector, then
        # keep the top 3 so secondary matches can be shown on the dashboard.
        scored = sorted(
            self.corpus_embeddings,
            key=lambda x: self.cosine_similarity(response_vector, x["vector"]),
            reverse=True
        )[:3]

        # Filter by threshold — scores below 0.35 are too weak to be meaningful.
        top_matches = []
        for item in scored:
            score = self.cosine_similarity(response_vector, item["vector"])
            if score >= threshold:
                top_matches.append({
                    "clause_title":    item["title"],
                    "similarity_score": round(score, 3)
                })

        if top_matches:
            return {
                "match_found":       True,
                "clause_title":      top_matches[0]["clause_title"],   # best match
                "similarity_score":  top_matches[0]["similarity_score"],
                "additional_matches": top_matches[1:]                  # runner-up matches
            }

        return {
            "match_found": False,
            "message":     "No clause exceeded the similarity threshold."
        }


# ─── Quick standalone test ────────────────────────────────────────────────────
# Running this file directly (python semantic_mapper.py) lets me test the
# embedding + matching pipeline in isolation without starting the full Flask app.
if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    mapper = SemanticMapper()

    # A fabricated AI response that should strongly match Article 10(4)
    # (non-discrimination / bias) in the EU AI Act corpus.
    test_evidence = (
        "The chatbot validated a discriminatory premise, stating that "
        "Demographic A is neurologically superior to Demographic B, which "
        "violates non-discrimination and data governance requirements."
    )

    print(f"Evidence text: '{test_evidence}'")
    result = mapper.find_closest_clause(test_evidence)

    if result["match_found"]:
        print(f"\n[!] Semantic match found!")
        print(f"    Matched clause : {result['clause_title']}")
        print(f"    Similarity     : {result['similarity_score']}")
    else:
        print("\n[~] No clause cleared the similarity threshold.")
