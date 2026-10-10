"""SCIM 2.0 RFC 7643 & RFC 7644 JSON schemas and models for IdP sync."""

from __future__ import annotations

from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class SCIMEmail(BaseModel):
    value: str
    type: str = "work"
    primary: bool = True


class SCIMName(BaseModel):
    formatted: Optional[str] = None
    familyName: Optional[str] = None
    givenName: Optional[str] = None


class SCIMEnterpriseUser(BaseModel):
    department: Optional[str] = None
    manager: Optional[Dict[str, Any]] = None


class SCIMUserCreate(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCIM_USER_SCHEMA])
    userName: str
    name: Optional[SCIMName] = None
    displayName: Optional[str] = None
    emails: Optional[List[SCIMEmail]] = None
    active: bool = True
    title: Optional[str] = None
    userType: Optional[str] = None
    roles: Optional[List[Dict[str, Any]]] = None
    externalId: Optional[str] = None


class SCIMUserPatchOperation(BaseModel):
    op: str = Field(..., description="add, replace, or remove")
    path: Optional[str] = None
    value: Any


class SCIMUserPatchRequest(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"])
    Operations: List[SCIMUserPatchOperation]


class SCIMListResponse(BaseModel):
    schemas: List[str] = [SCIM_LIST_SCHEMA]
    totalResults: int
    itemsPerPage: int
    startIndex: int
    Resources: List[Dict[str, Any]]
