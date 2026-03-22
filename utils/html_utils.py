import re


def extract_html(raw: str) -> str:
    """Strip markdown fences from LLM output."""
    match = re.search(r"```(?:html)?\s*(.*?)```", raw, re.DOTALL)
    return match.group(1).strip() if match else raw.strip()


def is_valid_html(content: str) -> bool:
    """Basic check that content looks like HTML."""
    return bool(re.search(r'<html|<!DOCTYPE|<body|<head', content, re.IGNORECASE))
