from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import json

app = FastAPI(title="Ollama API for hos-qwen2.5-coder-7b")

class PromptRequest(BaseModel):
    prompt: str
    max_tokens: int = 512
    temperature: float = 0.7

OLLAMA_API_URL = "http://localhost:11434/api/generate"

@app.post("/generate")
async def generate_response(request: PromptRequest):
    try:
        payload = {
            "model": "hos-qwen2.5-coder-7b",
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": False
        }
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()
        result = response.json()
        return {"response": result.get("response", ""), "model": "hos-qwen2.5-coder-7b"}
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error communicating with Ollama: {str(e)}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid response from Ollama")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/health")
async def health_check():
    try:
        response = requests.get("http://localhost:11434")
        response.raise_for_status()
        return {"status": "healthy", "ollama": "reachable"}
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Ollama service is not reachable")
