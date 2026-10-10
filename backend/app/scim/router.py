"""SCIM 2.0 Identity Provider Synchronization Router.

Complies with RFC 7643 & RFC 7644 for automated user provisioning, attribute sync,
and de-provisioning from Okta, Azure Active Directory (Microsoft Entra ID),
and Google Workspace.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_db
from app.models.user import User
from app.models.role import Role
from app.models.enums import AccountStatus
from app.models.session import UserSession
from app.models.enums import SessionStatus
from app.scim.schemas import (
    SCIM_USER_SCHEMA,
    SCIM_ENTERPRISE_USER_SCHEMA,
    SCIM_GROUP_SCHEMA,
    SCIM_LIST_SCHEMA,
    SCIM_ERROR_SCHEMA,
    SCIMUserCreate,
    SCIMUserPatchRequest,
)

router = APIRouter(prefix="/scim/v2", tags=["SCIM 2.0 Enterprise IdP Sync"])


def _user_to_scim_resource(user: User) -> Dict[str, Any]:
    """Convert User DB record to RFC 7643 SCIM User representation."""
    return {
        "schemas": [SCIM_USER_SCHEMA, SCIM_ENTERPRISE_USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.oauth_sub or str(user.id),
        "userName": user.username,
        "name": {
            "formatted": user.full_name,
            "familyName": user.full_name.split()[-1] if len(user.full_name.split()) > 1 else "",
            "givenName": user.full_name.split()[0] if user.full_name else "",
        },
        "displayName": user.full_name,
        "emails": [
            {
                "value": user.email,
                "type": "work",
                "primary": True,
            }
        ],
        "active": user.account_status == AccountStatus.ACTIVE,
        "roles": [
            {
                "value": user.role.name if user.role else "user",
                "primary": True,
            }
        ],
        SCIM_ENTERPRISE_USER_SCHEMA: {
            "department": user.department or "Engineering",
        },
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if hasattr(user, "created_at") and user.created_at else "",
            "lastModified": user.updated_at.isoformat() if hasattr(user, "updated_at") and user.updated_at else "",
            "location": f"/scim/v2/Users/{user.id}",
        },
    }


@router.get("/ServiceProviderConfig")
def get_service_provider_config():
    """RFC 7644 §4 Service Provider Configuration."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.vajranetra.io/scim",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 100},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication Scheme using the OAuth Bearer Token Standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "type": "oauthbearertoken",
                "primary": True,
            }
        ],
    }


@router.get("/ResourceTypes")
def get_resource_types():
    """RFC 7644 §4 Resource Types Discovery."""
    return [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/scim/v2/Users",
            "description": "User Account",
            "schema": SCIM_USER_SCHEMA,
            "schemaExtensions": [
                {
                    "schema": SCIM_ENTERPRISE_USER_SCHEMA,
                    "required": False,
                }
            ],
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/scim/v2/Groups",
            "description": "Security Group / Role",
            "schema": SCIM_GROUP_SCHEMA,
        },
    ]


@router.get("/Schemas")
def get_schemas():
    """RFC 7644 §4 Schemas Discovery."""
    return [
        {
            "id": SCIM_USER_SCHEMA,
            "name": "User",
            "description": "Core User Schema",
        },
        {
            "id": SCIM_GROUP_SCHEMA,
            "name": "Group",
            "description": "Core Group Schema",
        },
    ]


@router.get("/Users")
def list_users(
    startIndex: int = Query(1, ge=1),
    count: int = Query(50, ge=1, le=100),
    filter: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """RFC 7644 §3.4.2 Query and Filter Users."""
    query = select(User)

    if filter:
        # Simple SCIM filter parsing: userName eq "value" or emails.value eq "value"
        match = re.search(r'(?:userName|emails\.value)\s+eq\s+["\']([^"\']+)["\']', filter, re.IGNORECASE)
        if match:
            target_val = match.group(1).strip()
            query = query.where((User.username == target_val) | (User.email == target_val))

    all_users = db.execute(query).scalars().all()
    total = len(all_users)

    # Apply 1-based pagination
    offset = startIndex - 1
    paged = all_users[offset : offset + count]

    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": startIndex,
        "itemsPerPage": len(paged),
        "Resources": [_user_to_scim_resource(u) for u in paged],
    }


@router.post("/Users", status_code=status.HTTP_201_CREATED)
def create_user(payload: SCIMUserCreate, db: Session = Depends(get_db)):
    """RFC 7644 §3.3 Create User (Provisioning from Okta/Azure AD)."""
    # Check if user already exists
    existing = db.execute(
        select(User).where((User.username == payload.userName) | (User.email == payload.userName))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"User with userName '{payload.userName}' already exists",
        )

    # Determine role
    role_name = "user"
    if payload.roles and len(payload.roles) > 0:
        role_name = payload.roles[0].get("value", "user")
    elif payload.title and "admin" in payload.title.lower():
        role_name = "admin"

    role = db.execute(select(Role).where(Role.name == role_name)).scalar_one_or_none()
    if not role:
        role = db.execute(select(Role).where(Role.name == "user")).scalar_one_or_none()
    if not role:
        role = db.execute(select(Role)).scalars().first()

    email_val = payload.userName
    if payload.emails and len(payload.emails) > 0:
        email_val = payload.emails[0].value

    full_name = payload.displayName or (payload.name.formatted if payload.name else payload.userName)

    new_user = User(
        username=payload.userName,
        email=email_val,
        full_name=full_name,
        department="Engineering",
        role_id=role.id,
        account_status=AccountStatus.ACTIVE if payload.active else AccountStatus.DISABLED,
        oauth_sub=payload.externalId,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return _user_to_scim_resource(new_user)


@router.get("/Users/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db)):
    """RFC 7644 §3.4.1 Retrieve User by ID."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return _user_to_scim_resource(user)


@router.patch("/Users/{user_id}")
def patch_user(user_id: str, payload: SCIMUserPatchRequest, db: Session = Depends(get_db)):
    """RFC 7644 §3.5.2 Patch User (Status changes, suspension, attribute updates)."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    for op in payload.Operations:
        op_type = op.op.lower()
        path = (op.path or "").lower()
        val = op.value

        if op_type in ("replace", "add"):
            if path == "active" or (isinstance(val, dict) and "active" in val):
                is_active = val if isinstance(val, bool) else val.get("active")
                user.account_status = AccountStatus.ACTIVE if is_active else AccountStatus.DISABLED
                # Terminate sessions if deactivated
                if not is_active:
                    for s in user.sessions:
                        s.status = SessionStatus.TERMINATED
            elif path in ("displayname", "name.formatted"):
                user.full_name = str(val)
            elif path == "department" or (isinstance(val, dict) and "department" in val):
                user.department = val if isinstance(val, str) else val.get("department", "")

    db.commit()
    db.refresh(user)
    return _user_to_scim_resource(user)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str, db: Session = Depends(get_db)):
    """RFC 7644 §3.6 Deprovision User."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Mark disabled and terminate active sessions
    user.account_status = AccountStatus.DISABLED
    for s in user.sessions:
        s.status = SessionStatus.TERMINATED
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/Groups")
def list_groups(db: Session = Depends(get_db)):
    """RFC 7644 §3.4.2 Query Groups / Roles."""
    roles = db.execute(select(Role)).scalars().all()
    resources = []
    for r in roles:
        resources.append({
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": str(r.id),
            "displayName": r.name,
            "meta": {
                "resourceType": "Group",
                "location": f"/scim/v2/Groups/{r.id}",
            },
        })

    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(resources),
        "itemsPerPage": len(resources),
        "startIndex": 1,
        "Resources": resources,
    }
