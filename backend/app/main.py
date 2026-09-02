from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scan import router as scan_router


app = FastAPI(
    title="SentinelAI API",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(
    scan_router,
    prefix="/api"
)


@app.get("/")
def root():
    return {
        "message": "SentinelAI Backend Running"
    }