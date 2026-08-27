import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .config import get_settings
from .database import init_db
from .sync import run_sync
from .routers import auth, dashboard, vulnerabilities, hosts, scans, reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
)
log = logging.getLogger(__name__)
settings = get_settings()

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("OpenVAS Dashboard iniciando…")
    await init_db()

    # Agendar sync automático
    scheduler.add_job(
        run_sync,
        "interval",
        minutes=settings.sync_interval_minutes,
        id="auto_sync",
        max_instances=1,
    )
    scheduler.start()
    log.info("Scheduler iniciado — sync a cada %d min", settings.sync_interval_minutes)

    yield

    scheduler.shutdown(wait=False)
    log.info("Shutdown.")


app = FastAPI(
    title="OpenVAS Dashboard",
    description="API para gestão de vulnerabilidades OpenVAS/GVM",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(vulnerabilities.router)
app.include_router(hosts.router)
app.include_router(scans.router)
app.include_router(reports.router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
