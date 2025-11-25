# Biniam Demissie
# 09/29/2025
import os
import json
import time
import requests
from typing import Dict, Any, Generator
from openai import OpenAI, APIConnectionError

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
    "list_functions": "Listing functions...",
    "decompile_function": "Decompiling code...",
    "get_xrefs": "Tracing references...",
    "list_imports": "Checking imports...",
    "list_strings": "Extracting strings...",
    "query_artifacts": "Querying database...",
    "status": "Checking status..."
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
        # Using host.docker.internal if running in Docker, otherwise localhost
        self.client = OpenAI(
           base_url="http://localhost:11434/v1", 
           api_key="ollama"
        )
        
        # RECOMMENDED: Use qwen2.5-coder or mistral-nemo for better tool use
        self.model = "qwen3-coder:30b" 

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

        try:
            for i in range(TURNS):
                print(f"DEBUG: Turn {i+1}/{TURNS} - Sending to {self.model}...") 
                
                # Retry logic for model loading
                retries = 3
                first_response = None
                while retries > 0:
                    try:
                        first_response = self.client.chat.completions.create(
                            model=self.model,
                            messages=messages,
                            tools=TOOLS,
                            tool_choice="auto"
                        )
                        break
                    except APIConnectionError:
                        print("DEBUG: Connection Refused. Is Ollama running? Retrying in 2s...")
                        time.sleep(2)
                        retries -= 1
                
                if not first_response:
                    raise Exception("Could not connect to Ollama after 3 retries.")

                message = first_response.choices[0].message
                messages.append(message)
                
                # If model replies with text (no tool calls), we are done with the loop
                if not message.tool_calls:
                    break            

                if message.tool_calls:
                    for tool_call in message.tool_calls:
                        function_name = tool_call.function.name
                        if function_name in self.available_tools:
                            
                            intent = TOOL_INTENT_DESCRIPTIONS.get(function_name, f"Running {function_name}...")
                            yield json.dumps({"type": "tool_call", "description": intent})
                            
                            function_to_call = self.available_tools[function_name]
                            
                            # SAFETY: Some models return bad JSON for arguments
                            try:
                                args = json.loads(tool_call.function.arguments)
                            except:
                                args = {}

                            if 'job_id' not in args:
                                args['job_id'] = job_id
                                
                            print(f"DEBUG: Calling tool {function_name} with {args}")
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

        except Exception as e:
            print(f"CRITICAL ERROR: {e}")
            yield json.dumps({"type": "error", "content": f"AI Error: {str(e)}"})
