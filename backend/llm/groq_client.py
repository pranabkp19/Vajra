import os
import json
import httpx
from typing import Dict, Any, Optional
from backend.evidence.schemas import CompressedEvidencePacket, LLMAction, ActionTypeEnum

class GroqClient:
    """
    Groq API client interfacing with GPT-OSS 120B (with configurable fallback).
    Enforces structured JSON decision output for root-cause reasoning, strategy selection,
    and C/C++ patch synthesis.
    """
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.model = model or os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        self.endpoint = "https://api.groq.com/openai/v1/chat/completions"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key != "your_groq_api_key_here")

    async def get_reasoning_and_action(
        self,
        evidence_packet: CompressedEvidencePacket,
        system_prompt: str
    ) -> Tuple[LLMAction, str]:
        """
        Sends the compressed evidence packet to Groq GPT-OSS 120B and parses structured LLMAction.
        If API key is missing or call fails, falls back to deterministic local reasoning heuristics.
        """
        has_valid_key = bool(self.api_key and self.api_key != "your_groq_api_key_here")
        print(f"[VAJRA] Groq configured: {has_valid_key}")
        print(f"[VAJRA] Model configured: {self.model}")

        if not has_valid_key:
            print("[VAJRA] [LOCAL FALLBACK MODE] No valid GROQ_API_KEY detected in environment. Using local heuristic reasoning.")
            return self._heuristic_fallback_action(evidence_packet), "LOCAL_FALLBACK"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        user_content = json.dumps(evidence_packet.model_dump(), indent=2)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "max_tokens": 2048
        }

        mode_status = "LOCAL_FALLBACK"
        try:
            print(f"[VAJRA] [AI MODE] Model: {self.model}")
            print(f"[VAJRA] [AI MODE] Sending HTTP POST request to Groq API...")
            async with httpx.AsyncClient(timeout=45.0) as client:
                response = await client.post(self.endpoint, headers=headers, json=payload)
                print(f"[VAJRA] [AI MODE] Groq API Response Status Code: {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(content)
                    print(f"[VAJRA] [AI MODE] Groq response received")
                    print(f"[VAJRA] LLM response parsed successfully")
                    return LLMAction(**parsed), "LIVE_AI"
                elif response.status_code == 429:
                    mode_status = "RATE_LIMITED"
                    print(f"[VAJRA] [AI_REASONING_UNAVAILABLE] Groq API returned status 429: {response.text[:200]}")
                else:
                    mode_status = "AI_REASONING_UNAVAILABLE"
                    print(f"[VAJRA] [AI_REASONING_UNAVAILABLE] Groq API returned status {response.status_code}: {response.text[:200]}")
        except Exception as e:
            mode_status = "AI_REASONING_UNAVAILABLE"
            print(f"[VAJRA] [AI_REASONING_UNAVAILABLE] Failed to connect to Groq API: {str(e)}")

        return self._heuristic_fallback_action(evidence_packet), mode_status

    def _heuristic_fallback_action(self, packet: CompressedEvidencePacket) -> LLMAction:
        """
        Deterministic fallback reasoning engine when API key is unconfigured.
        """
        if packet.workflow_state == "DISCOVERED":
            return LLMAction(
                action_type=ActionTypeEnum.RUN_ASAN,
                target=packet.file,
                reason="Execute AddressSanitizer on vulnerable target to capture runtime memory violation bounds.",
                confidence=0.92
            )
        elif packet.workflow_state in ["ASAN_COMPLETED", "CRASH_CONFIRMED"]:
            return LLMAction(
                action_type=ActionTypeEnum.GENERATE_PATCH,
                target=packet.file,
                reason=f"Synthesize memory safety patch for {packet.cwe} at {packet.file}:{packet.line}",
                confidence=0.89,
                proposed_patch=self._synthesize_fallback_patch(packet)
            )
        elif packet.workflow_state == "PATCH_GENERATED":
            return LLMAction(
                action_type=ActionTypeEnum.VERIFY,
                target=packet.file,
                reason="Trigger deterministic verification pipeline (compile, PoV replay, ASan check).",
                confidence=0.95
            )
        else:
            return LLMAction(
                action_type=ActionTypeEnum.STOP,
                target=packet.file,
                reason="Vulnerability remediation workflow complete.",
                confidence=0.99
            )

    def _synthesize_fallback_patch(self, packet: CompressedEvidencePacket) -> str:
        """
        Synthesizes a C/C++ memory safety guard patch based on CWE type.
        """
        if "787" in packet.cwe or "120" in packet.cwe:
            # Buffer overflow / strcpy guard
            return f"""--- a/{packet.file}
+++ b/{packet.file}
@@ -{packet.line},5 +{packet.line},7 @@
-    strcpy(buffer, input);
+    if (strlen(input) < sizeof(buffer)) {{
+        strncpy(buffer, input, sizeof(buffer) - 1);
+        buffer[sizeof(buffer) - 1] = '\\0';
+    }}
"""
        elif "416" in packet.cwe:
            # Use after free guard
            return f"""--- a/{packet.file}
+++ b/{packet.file}
@@ -{packet.line},3 +{packet.line},4 @@
     free(ptr);
+    ptr = NULL;
"""
        elif "134" in packet.cwe:
            # Format string guard
            return f"""--- a/{packet.file}
+++ b/{packet.file}
@@ -{packet.line},3 +{packet.line},4 @@
-    printf(user_msg);
+    printf("%s", user_msg);
"""
        elif "190" in packet.cwe:
            # Integer overflow guard
            return f"""--- a/{packet.file}
+++ b/{packet.file}
@@ -{packet.line},3 +{packet.line},4 @@
+    if (count > 100000) return;
"""
        else:
            return f"""--- a/{packet.file}
+++ b/{packet.file}
@@ -{packet.line},3 +{packet.line},4 @@
+    // VAJRA Bounds Guard
"""
