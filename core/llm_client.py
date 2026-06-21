"""
core/llm_client.py — Shared LLM client (Groq → Ollama → OpenAI → none)
Groq uses the OpenAI-compatible API at https://api.groq.com/openai/v1
"""
from typing import Optional, Tuple

import config

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


def get_llm_provider() -> str:
    """Return active provider name: groq, ollama, openai, or none."""
    if config.USE_OLLAMA:
        return "ollama"
    if config.GROQ_API_KEY:
        return "groq"
    if config.OPENAI_API_KEY:
        return "openai"
    return "none"


def active_llm_model() -> str:
    """Return model id for the active provider."""
    provider = get_llm_provider()
    if provider == "ollama":
        return config.OLLAMA_MODEL
    if provider == "groq":
        return config.GROQ_MODEL
    return config.LLM_MODEL


def build_llm_client() -> Tuple[Optional[object], str]:
    """
    Build an OpenAI-compatible client for the best available provider.
    Returns (client, provider_name). client is None if no LLM configured.
    """
    try:
        from openai import OpenAI
    except ImportError:
        return None, "none"

    if config.USE_OLLAMA:
        return OpenAI(api_key="ollama", base_url=config.OLLAMA_BASE_URL), "ollama"

    if config.GROQ_API_KEY:
        return OpenAI(api_key=config.GROQ_API_KEY, base_url=GROQ_BASE_URL), "groq"

    if config.OPENAI_API_KEY:
        return OpenAI(api_key=config.OPENAI_API_KEY), "openai"

    return None, "none"


def llm_configured() -> bool:
    return get_llm_provider() != "none"
