import os
import json
import base64
import datetime
from typing import List, Optional
from fastapi import FastAPI, Request, Form, HTTPException, status, Header
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Hardcoded Admin Password and Auth Token
ADMIN_PASSWORD = "admin"
SECRET_TOKEN = "parental-secret-key-123"

app = FastAPI(title="Parental Control Self-Hosted System")
templates = Jinja2Templates(directory="templates")

# --- In-Memory Data Storage ---
memory_store = {
    "device": None, # dict holding device_id, device_name, last_seen
    "running_apps": [], # list of {"package_name": ..., "app_name": ...}
    "blocked_packages": [], # list of package names
    "kill_commands": [], # list of package names requested to be closed
    "screenshot_pending": False,
    "screenshots": [], # list of {"image_base64": ..., "captured_at": ...}
    "logs": [] # list of {"event": ..., "created_at": ...}
}

def log_event(event_text: str):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S - %b %d")
    memory_store["logs"].insert(0, {"event": event_text, "created_at": timestamp})
    memory_store["logs"] = memory_store["logs"][:25] # keep last 25

def is_authenticated(request: Request) -> bool:
    return request.cookies.get("auth_session") == SECRET_TOKEN

# --- Web Dashboard Routes ---

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    
    policy = {
        "blocked_packages": memory_store["blocked_packages"],
        "screenshot_pending": memory_store["screenshot_pending"]
    }
    
    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "device": memory_store["device"],
        "running_apps": memory_store["running_apps"],
        "policy": policy,
        "screenshots": memory_store["screenshots"],
        "logs": memory_store["logs"]
    })

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})

@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie("auth_session", SECRET_TOKEN, httponly=True)
        return response
    return templates.TemplateResponse(request=request, name="login.html", context={"error": "Incorrect admin password"})

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("auth_session")
    return response

# Dashboard Actions

@app.post("/action/block_app")
def block_app(request: Request, package_name: str = Form(...)):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    
    if package_name not in memory_store["blocked_packages"]:
        memory_store["blocked_packages"].append(package_name)
        log_event(f"Blocked package: {package_name}")
        
    return RedirectResponse(url="/", status_code=303)

@app.post("/action/unblock_app")
def unblock_app(request: Request, package_name: str = Form(...)):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    
    if package_name in memory_store["blocked_packages"]:
        memory_store["blocked_packages"].remove(package_name)
        log_event(f"Unblocked package: {package_name}")
        
    return RedirectResponse(url="/", status_code=303)

@app.post("/action/kill_app")
def kill_app(request: Request, package_name: str = Form(...)):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    
    if package_name not in memory_store["kill_commands"]:
        memory_store["kill_commands"].append(package_name)
        log_event(f"Requested remote close for: {package_name}")
        
    return RedirectResponse(url="/", status_code=303)

@app.post("/action/request_screenshot")
def request_screenshot(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    
    memory_store["screenshot_pending"] = True
    log_event("Requested live screenshot capture")
    return RedirectResponse(url="/", status_code=303)

# --- REST API for Android Child Device ---

class AppItem(BaseModel):
    package_name: str
    app_name: str

class SyncDevicePayload(BaseModel):
    device_id: str
    device_name: str
    running_apps: List[AppItem]

@app.post("/api/sync")
def api_sync(
    payload: SyncDevicePayload,
    x_auth_token: Optional[str] = Header(None)
):
    if x_auth_token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid hardcoded token")

    # Update memory store
    memory_store["device"] = {
        "device_id": payload.device_id,
        "device_name": payload.device_name,
        "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    memory_store["running_apps"] = [
        {"package_name": item.package_name, "app_name": item.app_name}
        for item in payload.running_apps
    ]
    
    # Read pending kill commands
    active_kills = list(memory_store["kill_commands"])
    memory_store["kill_commands"].clear() # clear queue
    
    return {
        "status": "ok",
        "blocked_packages": memory_store["blocked_packages"],
        "kill_commands": active_kills,
        "screenshot_pending": memory_store["screenshot_pending"]
    }

class ScreenshotPayload(BaseModel):
    device_id: str
    image_base64: str

@app.post("/api/screenshot/upload")
def upload_screenshot(
    payload: ScreenshotPayload,
    x_auth_token: Optional[str] = Header(None)
):
    if x_auth_token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid hardcoded token")

    timestamp = datetime.datetime.now().strftime("%H:%M:%S - %b %d")
    memory_store["screenshots"].insert(0, {
        "image_base64": payload.image_base64,
        "captured_at": timestamp
    })
    memory_store["screenshots"] = memory_store["screenshots"][:8] # keep last 8
    memory_store["screenshot_pending"] = False
    
    log_event("Uploaded fresh screenshot frame")
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
