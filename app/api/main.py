"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.models.database import init_db
from app.api.routers.alerts import router as alerts_router
from app.api.routers.stats import router as stats_router

from app.api.routers.ingest import router as ingest_router
from fastapi.staticfiles import StaticFiles

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database when the application starts."""
    init_db()
    yield

app = FastAPI(
    title="Threat detection Platform",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the health status of the API."""
    return {"status": "ok"}

app.include_router(alerts_router)
app.include_router(stats_router)
app.include_router(ingest_router)
