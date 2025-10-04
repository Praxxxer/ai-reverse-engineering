# Biniam Demissie
# 09/29/2025
import os
import json
import requests
from typing import Dict, Any, Generator
from openai import OpenAI

GHIDRA_API_BASE = "http://localhost:9090"

SYSTEM_PROMPT = "You are a helpful reverse engineering assistant. You have access to a set of tools to analyze a binary identified by a job_id. When the user asks a question, use the available tools to find the answer. If something is not clear, ask for clarification before answering. Format your final response in Markdown."
TURNS = 5 

TOOLS = [
  { "type": "function", "function": { "name": "analyze", "description": "Upload a base64-encoded binary and start headless Ghidra analysis. Returns job_id.", "parameters": { "type": "object", "properties": { "file_b64": {"type": "string"}, "filename": {"type": "string"}}, "required": ["file_b64", "filename"] }}},
  { "type": "function", "function": { "name": "status", "description": "Get status for an existing analysis job.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_functions", "description": "Retrieve the list of discovered functions for a job.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "decompile_function", "description": "Get decompiled pseudocode for a function at a given address.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "get_xrefs", "description": "Get callers and callees for a function (cross-references).", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "addr": {"type": "string"} }, "required": ["job_id", "addr"] }}},
  { "type": "function", "function": { "name": "list_imports", "description": "List imported libraries and symbols for the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "list_strings", "description": "Return printable strings extracted from the binary.", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "min_length": {"type": "integer"} }, "required": ["job_id"] }}},
  { "type": "function", "function": { "name": "query_artifacts", "description": "Simple natural-language-like query over artifacts (function names, decompiled snippets).", "parameters": { "type": "object", "properties": { "job_id": {"type": "string"}, "query": {"type": "string"} }, "required": ["job_id", "query"] }}}
]

TOOL_INTENT_DESCRIPTIONS = {
    "list_functions": "list_functions",
    "decompile_function": "decompile_function",
    "get_xrefs": "get_xrefs",
    "list_imports": "list_imports",
    "list_strings": "list_strings",
    "query_artifacts": "query_artifacts",
    "status": "status"
}

def call_ghidra_tool(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        response = requests.post(f"{GHIDRA_API_BASE}/tools/{endpoint}", json=payload)
        response.raise_for_status()
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"result": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

class GhidraAssistant:
    def __init__(self):
        # OpenAI compatible client
        self.client = OpenAI(
           base_url= os.getenv("API_BASE"),
           api_key=os.getenv("API_KEY", "not-used")
        )
        self.model = os.getenv("MODEL_NAME")

        self.available_tools = {
            "status": lambda **kwargs: call_ghidra_tool("status", kwargs),
            "list_functions": lambda **kwargs: call_ghidra_tool("list_functions", kwargs),
            "decompile_function": lambda **kwargs: call_ghidra_tool("decompile_function", kwargs),
            "get_xrefs": lambda **kwargs: call_ghidra_tool("get_xrefs", kwargs),
            "list_imports": lambda **kwargs: call_ghidra_tool("list_imports", kwargs),
            "list_strings": lambda **kwargs: call_ghidra_tool("list_strings", kwargs),
            "query_artifacts": lambda **kwargs: call_ghidra_tool("query_artifacts", kwargs),
        }
        
    def chat_completion_stream(self, user_message: str, job_id: str) -> Generator[str, None, None]:
        contextual_message = f"For job_id '{job_id}', {user_message}"
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": contextual_message}
        ]

        for i in range(TURNS):
            first_response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto"
            )
            message = first_response.choices[0].message
            messages.append(message)
            
            if not message.tool_calls:
                break            

            if message.tool_calls:
                for tool_call in message.tool_calls:
                    function_name = tool_call.function.name
                    if function_name in self.available_tools:
                        
                        intent_description = TOOL_INTENT_DESCRIPTIONS.get(function_name, f"Executing tool: {function_name}...")
                        yield json.dumps({"type": "tool_call", "description": intent_description})
                        

                        function_to_call = self.available_tools[function_name]
                        args = json.loads(tool_call.function.arguments)
                        if 'job_id' not in args:
                            args['job_id'] = job_id
                            
                        result = function_to_call(**args)
                        
                        messages.append({
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "name": function_name,
                            "content": json.dumps(result)
                        })

        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True
        )

        for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                yield json.dumps({"type": "token", "content": content})