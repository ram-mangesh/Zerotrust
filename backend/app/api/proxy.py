"""PEP Reverse Proxy Gateway API router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.context import ContextBundle
from app.core.database import get_db
from app.core.dependencies import get_context_bundle
from app.services.pep_service import PEPService

router = APIRouter(tags=["pep-gateway"])


@router.api_route(
    "/proxy/{resource_slug}/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    summary="PEP Reverse Proxy Gateway Ingress",
)
async def pep_reverse_proxy(
    resource_slug: str,
    subpath: str,
    request: Request,
    db: Session = Depends(get_db),
    bundle: ContextBundle = Depends(get_context_bundle),
) -> Response:
    """Policy Enforcement Point (PEP) Ingress route for protected upstream services."""
    return await PEPService.enforce_and_proxy(
        request=request,
        resource_slug=resource_slug,
        subpath=subpath,
        db=db,
        bundle=bundle,
    )
