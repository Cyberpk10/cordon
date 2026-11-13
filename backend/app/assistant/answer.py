"""Chooses the assistant's answer: the grounded LLM answer when it's enabled and passes every
check in app.assistant.llm, otherwise the deterministic one. Pure apart from the optional
LLM call."""

from __future__ import annotations

from app.assistant import deterministic, llm
from app.assistant.deterministic import OFF_TOPIC_REDIRECT, AssistantAnswer
from app.assistant.facts import EmailFacts
from app.core.config import settings


def answer_question(facts: EmailFacts, question: str, history: list[dict[str, str]]) -> AssistantAnswer:
    if settings.enable_llm_reasoning:
        result = llm.generate_answer(facts, question, history)
        if result is not None:
            if not result.on_topic:
                return AssistantAnswer(answer=OFF_TOPIC_REDIRECT, refused=True)
            return AssistantAnswer(answer=result.answer)
    return deterministic.answer(facts, question)
