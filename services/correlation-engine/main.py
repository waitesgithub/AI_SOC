"""
Alert Correlation Engine - FastAPI Application
AI-Augmented SOC

Groups related security alerts into incidents based on IP affinity,
temporal proximity, and MITRE ATT&CK kill chain progression.
"""

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, Depends, Request, status
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from config import get_settings
from database import (
    create_db_pool,
    close_db_pool,
    check_db_health,
    get_db,
    IncidentModel,
    IncidentAlertModel,
)
from models import (
    CorrelationRequest,
    CorrelationResponse,
    Incident,
    IncidentSummary,
    IncidentAlert,
    StatusUpdate,
    HealthResponse,
)
from correlator import CorrelationEngine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

settings = get_settings()

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

CORRELATION_REQUESTS = Counter(
    "correlation_requests_total",
    "Total correlation requests processed",
    ["status"],
)
CORRELATION_DURATION = Histogram(
    "correlation_request_duration_seconds",
    "Correlation request processing duration",
)
INCIDENTS_CREATED = Counter(
    "incidents_created_total",
    "Total new incidents opened",
)
INCIDENTS_UPDATED = Counter(
    "incidents_updated_total",
    "Total alerts attached to existing incidents",
)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database connection pool on startup, close on shutdown."""
    logger.info(
        "Starting %s v%s", settings.service_name, settings.service_version
    )

    try:
        await create_db_pool(settings.database_url)
        logger.info("Database pool initialised successfully")
    except Exception as exc:
        # Graceful degradation: service starts but reports DB as unavailable
        logger.warning("Database not available at startup: %s", exc)

    yield

    logger.info("Shutting down %s", settings.service_name)
    await close_db_pool()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Alert Correlation Engine",
    description=(
        "Groups related security alerts into incidents based on IP affinity, "
        "temporal proximity, and MITRE ATT&CK kill chain progression."
    ),
    version=settings.service_version,
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _incident_model_to_summary(row: IncidentModel) -> IncidentSummary:
    return IncidentSummary(
        incident_id=row.incident_id,
        status=row.status,
        severity=row.severity or "unknown",
        kill_chain_stage=row.kill_chain_stage or "unknown",
        alert_count=row.alert_count or 0,
        first_seen=row.first_seen or datetime.now(timezone.utc),
        last_seen=row.last_seen or datetime.now(timezone.utc),
        source_ips=row.source_ips or [],
        dest_ips=row.dest_ips or [],
        summary=row.summary or "",
    )


def _incident_model_to_full(
    row: IncidentModel, alert_rows: List[IncidentAlertModel]
) -> Incident:
    alerts = [
        IncidentAlert(
            alert_id=a.alert_id,
            added_at=a.added_at,
            severity=a.severity or "unknown",
            category=a.category or "unknown",
            kill_chain_stage=a.kill_chain_stage,
        )
        for a in alert_rows
    ]
    return Incident(
        incident_id=row.incident_id,
        status=row.status,
        severity=row.severity or "unknown",
        kill_chain_stage=row.kill_chain_stage or "unknown",
        kill_chain_stages_seen=row.kill_chain_stages_seen or [],
        alert_count=row.alert_count or 0,
        first_seen=row.first_seen or datetime.now(timezone.utc),
        last_seen=row.last_seen or datetime.now(timezone.utc),
        source_ips=row.source_ips or [],
        dest_ips=row.dest_ips or [],
        mitre_techniques=row.mitre_techniques or [],
        mitre_tactics=row.mitre_tactics or [],
        alerts=alerts,
        summary=row.summary or "",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/correlate",
    response_model=CorrelationResponse,
    status_code=status.HTTP_200_OK,
    summary="Correlate an alert into an incident",
    description=(
        "Score the incoming alert against all active incidents. "
        "Attach to the best match if score >= threshold, otherwise open a new incident."
    ),
)
async def correlate_alert(
    request: CorrelationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Receives a correlation request, scores it against active incidents,
    and returns the incident assignment.
    """
    start = time.time()

    try:
        engine = CorrelationEngine(db, settings)
        result = await engine.correlate(request)

        duration = time.time() - start
        CORRELATION_REQUESTS.labels(status="success").inc()
        CORRELATION_DURATION.observe(duration)

        if result.is_new_incident:
            INCIDENTS_CREATED.inc()
            logger.info(
                "New incident created: %s for alert %s",
                result.incident_id,
                request.alert_id,
            )
        else:
            INCIDENTS_UPDATED.inc()
            logger.info(
                "Alert %s attached to incident %s (score=%.3f)",
                request.alert_id,
                result.incident_id,
                result.correlation_score,
            )

        return result

    except Exception as exc:
        CORRELATION_REQUESTS.labels(status="error").inc()
        logger.error(
            "Correlation failed for alert %s: %s", request.alert_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation failed: {str(exc)}",
        )


@app.get(
    "/incidents",
    response_model=List[IncidentSummary],
    summary="List incidents",
    description="Paginated list of all incidents, optionally filtered by status.",
)
async def list_incidents(
    limit: int = Query(50, ge=1, le=500, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by status: open, investigating, closed"
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Return a paginated list of incidents, newest first.
    """
    try:
        query = select(IncidentModel).order_by(IncidentModel.last_seen.desc())

        if status_filter:
            valid_statuses = {"open", "investigating", "closed"}
            if status_filter not in valid_statuses:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid status '{status_filter}'. Must be one of: {valid_statuses}",
                )
            query = query.where(IncidentModel.status == status_filter)

        query = query.limit(limit).offset(offset)
        result = await db.execute(query)
        rows = result.scalars().all()

        return [_incident_model_to_summary(row) for row in rows]

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to list incidents: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve incidents: {str(exc)}",
        )


@app.get(
    "/incidents/active",
    response_model=List[IncidentSummary],
    summary="List active incidents",
    description="Return all incidents with status 'open' or 'investigating'.",
)
async def list_active_incidents(
    db: AsyncSession = Depends(get_db),
):
    """Return only open and investigating incidents, newest first."""
    try:
        result = await db.execute(
            select(IncidentModel)
            .where(IncidentModel.status.in_(["open", "investigating"]))
            .order_by(IncidentModel.last_seen.desc())
        )
        rows = result.scalars().all()
        return [_incident_model_to_summary(row) for row in rows]

    except Exception as exc:
        logger.error("Failed to list active incidents: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve active incidents: {str(exc)}",
        )


@app.get(
    "/incidents/{incident_id}",
    response_model=Incident,
    summary="Get incident details",
    description="Return full incident including all member alerts and kill chain timeline.",
)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Return full incident details with member alerts ordered by time.
    """
    try:
        # Fetch incident row
        result = await db.execute(
            select(IncidentModel).where(
                IncidentModel.incident_id == incident_id
            )
        )
        row = result.scalar_one_or_none()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

        # Fetch member alerts
        alerts_result = await db.execute(
            select(IncidentAlertModel)
            .where(IncidentAlertModel.incident_id == incident_id)
            .order_by(IncidentAlertModel.added_at.asc())
        )
        alert_rows = list(alerts_result.scalars().all())

        return _incident_model_to_full(row, alert_rows)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to get incident %s: %s", incident_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve incident: {str(exc)}",
        )


@app.put(
    "/incidents/{incident_id}/status",
    response_model=IncidentSummary,
    summary="Update incident status",
    description="Transition incident to open, investigating, or closed.",
)
async def update_incident_status(
    incident_id: str,
    body: StatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update the status of an incident. Automatically sets closed_at when
    the status is changed to 'closed'.
    """
    valid_statuses = {"open", "investigating", "closed"}
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{body.status}'. Must be one of: {valid_statuses}",
        )

    try:
        # Check existence first
        result = await db.execute(
            select(IncidentModel).where(
                IncidentModel.incident_id == incident_id
            )
        )
        row = result.scalar_one_or_none()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

        # Build update payload
        update_values = {"status": body.status}
        if body.status == "closed":
            update_values["closed_at"] = datetime.now(timezone.utc)

        await db.execute(
            update(IncidentModel)
            .where(IncidentModel.incident_id == incident_id)
            .values(**update_values)
        )
        await db.flush()

        # Re-fetch updated row
        result = await db.execute(
            select(IncidentModel).where(
                IncidentModel.incident_id == incident_id
            )
        )
        updated = result.scalar_one()

        logger.info(
            "Incident %s status updated to '%s'", incident_id, body.status
        )
        return _incident_model_to_summary(updated)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Failed to update incident %s status: %s", incident_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update incident status: {str(exc)}",
        )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Return service and database connection status.",
)
async def health_check():
    """
    Returns overall health including database connectivity.
    Status is 'healthy' if DB is reachable, 'degraded' otherwise.
    """
    db_ok = await check_db_health()
    svc_status = "healthy" if db_ok else "degraded"

    return HealthResponse(
        status=svc_status,
        service=settings.service_name,
        version=settings.service_version,
        db_connected=db_ok,
    )


@app.get("/metrics", summary="Prometheus metrics")
async def metrics():
    """Expose Prometheus metrics for scraping."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", summary="Service information")
async def root():
    """Root endpoint with service metadata."""
    return {
        "service": settings.service_name,
        "version": settings.service_version,
        "status": "operational",
        "endpoints": {
            "correlate": "POST /correlate",
            "incidents": "GET /incidents",
            "active_incidents": "GET /incidents/active",
            "incident_detail": "GET /incidents/{incident_id}",
            "update_status": "PUT /incidents/{incident_id}/status",
            "health": "GET /health",
            "metrics": "GET /metrics",
            "docs": "GET /docs",
        },
    }


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all for unhandled exceptions."""
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "path": str(request.url),
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=True,
    )
