# mpierce/config.py
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    provider: str = "bedrock"
    model_id: str = "qwen.qwen3-next-80b-a3b"
    temperature: float = 0.2

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            provider=os.getenv("LLM_PROVIDER", "bedrock"),
            model_id=os.getenv("LLM_MODEL_ID", "qwen.qwen3-next-80b-a3b"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
        )


def get_llm(settings: Settings | None = None):
    """Build a LangChain Bedrock chat model. Imported lazily so unit tests
    that only need Settings don't require boto3 credentials."""
    settings = settings or Settings.from_env()
    from langchain_aws import ChatBedrock

    return ChatBedrock(
        model_id=settings.model_id,
        model_kwargs={"temperature": settings.temperature},
    )
