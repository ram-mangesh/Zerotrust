"""Tests for SCIM 2.0 Identity Provider Synchronization (Okta, Azure AD, Google Workspace)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.role import Role
from app.models.enums import AccountStatus


def test_scim_service_provider_config(client: TestClient):
    """SCIM ServiceProviderConfig metadata discovery."""
    res = client.get("/scim/v2/ServiceProviderConfig")
    assert res.status_code == 200
    data = res.json()
    assert "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" in data["schemas"]
    assert data["patch"]["supported"] is True


def test_scim_resource_types_and_schemas(client: TestClient):
    """SCIM ResourceTypes & Schemas endpoints."""
    res_rt = client.get("/scim/v2/ResourceTypes")
    assert res_rt.status_code == 200
    assert any(rt["id"] == "User" for rt in res_rt.json())

    res_sc = client.get("/scim/v2/Schemas")
    assert res_sc.status_code == 200


def test_scim_user_lifecycle_crud(client: TestClient, db: Session, roles: dict[str, Role]):
    """Test full SCIM 2.0 user lifecycle: Create, List, Filter, Get, Patch, and Delete."""
    username = "scim.provisioned@securecorp.local"

    # 1. Create User via SCIM (Okta / Azure AD provisioning)
    create_payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "name": {
            "formatted": "Scim Provisioned User",
            "givenName": "Scim",
            "familyName": "User",
        },
        "emails": [{"value": username, "primary": True}],
        "active": True,
        "title": "Software Engineer",
    }
    res_create = client.post("/scim/v2/Users", json=create_payload)
    assert res_create.status_code == 201
    user_data = res_create.json()
    user_id = user_data["id"]
    assert user_data["userName"] == username
    assert user_data["active"] is True

    # 2. Get User by ID
    res_get = client.get(f"/scim/v2/Users/{user_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == user_id

    # 3. List Users with Filter
    res_filter = client.get(f'/scim/v2/Users?filter=userName eq "{username}"')
    assert res_filter.status_code == 200
    filter_data = res_filter.json()
    assert filter_data["totalResults"] >= 1
    assert any(u["id"] == user_id for u in filter_data["Resources"])

    # 4. Patch User (Suspend / Deactivate user from Azure AD)
    patch_payload = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "active",
                "value": False,
            }
        ],
    }
    res_patch = client.patch(f"/scim/v2/Users/{user_id}", json=patch_payload)
    assert res_patch.status_code == 200
    assert res_patch.json()["active"] is False

    # Verify in DB that account_status is DISABLED
    user_db = db.query(User).filter(User.username == username).first()
    db.refresh(user_db)
    assert user_db.account_status == AccountStatus.DISABLED

    # 5. Delete User (Deprovision)
    res_delete = client.delete(f"/scim/v2/Users/{user_id}")
    assert res_delete.status_code == 204

    # 6. List Groups / Roles
    res_groups = client.get("/scim/v2/Groups")
    assert res_groups.status_code == 200
    assert res_groups.json()["totalResults"] >= 1
