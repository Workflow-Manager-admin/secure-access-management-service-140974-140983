from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import router as auth_router

app = FastAPI(
    title="Secure Access Management API",
    description="Authentication backend for user registration, login, token management, and profile access.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration, login, profile, and JWT management."}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# Register authentication endpoints
app.include_router(auth_router)
