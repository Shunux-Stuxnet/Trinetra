import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
CHROMA_DIR = DATA_DIR / "chroma"
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(dotenv_path=ENV_FILE, override=True)
logging.getLogger("langsmith").setLevel(logging.CRITICAL)


def configure_langsmith_safely() -> None:
    """Enable LangSmith only after validating the configured regional endpoint."""
    ls_key = os.getenv("LANGCHAIN_API_KEY", "").strip().strip('"').strip("'")
    if not ls_key or "your_" in ls_key:
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        os.environ["LANGSMITH_TRACING"] = "false"
        print("[Pre-Flight 1/2] LangSmith: No key set -> Running in Local Console Mode.")
        return

    last_status: object = None
    for base_url in (
        "https://apac.api.smith.langchain.com",
        "https://api.smith.langchain.com",
        "https://eu.api.smith.langchain.com",
    ):
        try:
            response = requests.get(
                f"{base_url}/api/v1/sessions",
                params={"limit": 1},
                headers={"x-api-key": ls_key},
                timeout=4,
            )
            last_status = response.status_code
            if response.status_code == 200:
                os.environ["LANGCHAIN_ENDPOINT"] = base_url
                os.environ["LANGSMITH_ENDPOINT"] = base_url
                os.environ["LANGCHAIN_API_KEY"] = ls_key
                os.environ["LANGSMITH_API_KEY"] = ls_key
                os.environ["LANGCHAIN_TRACING_V2"] = "true"
                os.environ["LANGSMITH_TRACING"] = "true"
                os.environ.setdefault("LANGCHAIN_PROJECT", "Project-Trinetra")
                print(f"[Pre-Flight 1/2] LangSmith: ACTIVE ({base_url})")
                return
        except requests.RequestException as error:
            last_status = type(error).__name__

    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ.pop("LANGCHAIN_API_KEY", None)
    os.environ.pop("LANGSMITH_API_KEY", None)
    print(f"[Pre-Flight 1/2] LangSmith Failover: HTTP {last_status} -> Local Mode.")


configure_langsmith_safely()
