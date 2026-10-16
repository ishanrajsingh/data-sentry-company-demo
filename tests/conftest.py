import os

# Unit and corpus tests remain deterministic and do not require a running local
# Ollama service. Semantic-review behavior is covered with a stub classifier.
os.environ["INTENTLOCK_SEMANTIC_REVIEW"] = "off"
