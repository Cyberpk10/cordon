"""Conversational assistant for one email (POST /v1/assistant, used by the Outlook add-in).

- facts.py: the grounded facts (Cordon's own analysis + the email's own data), as a
  numbered evidence list. Pure.
- deterministic.py: LLM-free answers for the common questions, the off-topic redirect, and
  the fallback whenever the LLM is off or its answer is discarded. Pure.
- llm.py: the optional grounded LLM answer, same architecture and injection hardening as
  app.reasoning.llm_analyst / app.investigation.llm_summary.
- answer.py: picks between them. The only entry point the route calls.
"""
