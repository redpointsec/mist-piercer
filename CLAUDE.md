# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mist-piercer** is a prototyping sandbox for LLM-powered security analysis of HTTP traffic. Each `analyzer_*.py` is a self-contained script that parses a Burp Suite session XML export, then streams every request/response pair through an AWS Bedrock LLM (via LangChain) to flag a single vulnerability class.

It sits alongside (and prototypes ideas for) the broader Redpoint Surveyor platform — see the parent `../CLAUDE.md`. The same patterns appear, more productionized, in that repo's `llm_analysis/` analyzers.

## The Three Analyzers

| Script | Looks for | Model | Input |
|--------|-----------|-------|-------|
| `analyzer_authz.py` | Authorization issues (IDOR, missing authz checks) | Claude 3.5 Haiku | request + response |
| `analyzer_user_enum.py` | User / email enumeration | Qwen3 (`qwen.qwen3-next-80b-a3b`) | request only |
| `analyzer_extract_users.py` | Usernames/emails present in traffic | Qwen3 | request + response |

All three share the same skeleton:
1. `ET.parse('test/vtm-session.xml')` — **the input path is hardcoded** in each script.
2. Build a `ChatBedrock` LLM + a `ChatPromptTemplate` (system "reflection process" prompt + human question).
3. Iterate `<item>` elements; base64-decode `request`/`response` when the `base64="true"` attribute is set.
4. `chain.stream(...)` the pair and print the LLM output to stdout. Findings are not persisted — output is human-read only.

`BedrockEmbeddings` and FAISS are imported but currently unused (leftover RAG scaffolding); Ollama lines are commented out as the local-LLM alternative.

## Running

```bash
source venv/bin/activate          # Python 3.14 venv (no requirements.txt — deps live in venv)
python analyzer_authz.py          # or analyzer_user_enum.py / analyzer_extract_users.py
```

To analyze a different session, edit the `xml_file = 'test/vtm-session.xml'` line in the script (no CLI args).

### Requirements
- **AWS credentials** with Bedrock access in `us-west-2` (account uses `us.anthropic.*` and `qwen.*` model IDs). `load_dotenv()` runs at startup, so a `.env` (gitignored, not checked in) is the place for AWS env vars / overrides.
- Key deps already in `venv`: `langchain-aws`, `langchain-community`, `langchain-core`, `boto3`, `python-dotenv`. There is **no `requirements.txt`** — if you add deps, install into the venv and consider creating one.

## Burp Session XML Format

`test/vtm-session.xml` is a Burp Suite export (`burpVersion="2025.1.4"`, 46 items). Each `<item>` has `url` (CDATA), `host`, `method`, `status`, `mimetype`, and `request`/`response` elements. The `request` and `response` carry a `base64` attribute — decode with `base64.b64decode(...).decode('utf-8')` only when it is `"true"`. The `test/` directory holds this sample data, **not** unit tests; there is no test suite.

## Conventions When Extending

- To add a new analyzer, copy an existing `analyzer_*.py` and change only the `system_prompt_template`, the `question` block, and the `model_id`. Keep the strict "ONLY respond with the following information / DO NOT provide additional information" output contract — downstream readers depend on the terse format.
- The commented-out duplicate-URL skip block (`urls` list) is intentional scaffolding left for when sessions get large; uncomment to dedupe by URL.
- Per the parent repo's workflow rules: never push directly to `main`; branch, commit, and open a PR.
