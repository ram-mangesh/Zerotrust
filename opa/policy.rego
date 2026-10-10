# Zero Trust Network Access Platform - Open Policy Agent (OPA) Policy
#
# Combines:
#   - RBAC: role -> capabilities & permissions table
#   - ABAC: attribute matching (department, clearance ceiling, country, time window)
#   - Contextual Trust Gating: live trust score vs resource sensitivity floor
#
# Input shape:
# {
#   "subject": {
#     "id": "uuid",
#     "username": "alice",
#     "roles": ["employee"],
#     "permissions": ["resources:read"],
#     "attributes": {"department": "engineering", "clearance_ordinal": 2}
#   },
#   "resource": "source-repo",
#   "resource_sensitivity": "CONFIDENTIAL",
#   "action": "read",
#   "trust_score": 80.5,
#   "device_trusted": true,
#   "mfa_verified": true,
#   "is_vpn": false,
#   "country": "IN"
# }

package ztp.authz

import future.keywords.in
import future.keywords.if

default decision := {
	"allow": false,
	"action": "BLOCK",
	"reasons": ["no matching policy rule"],
}

# ---------------------------------------------------------------------------
# Sensitivity Floor Mappings (0=PUBLIC, 60=INTERNAL, 75=CONFIDENTIAL, 90=RESTRICTED)
# ---------------------------------------------------------------------------
sensitivity_floor := {
	"PUBLIC": 0,
	"INTERNAL": 60,
	"CONFIDENTIAL": 75,
	"RESTRICTED": 90,
}

sensitivity_ordinal := {
	"PUBLIC": 0,
	"INTERNAL": 1,
	"CONFIDENTIAL": 2,
	"RESTRICTED": 3,
}

# ---------------------------------------------------------------------------
# 1. RBAC Clearance & Permission Check
# ---------------------------------------------------------------------------
rbac_allow if {
	"admin" in input.subject.roles
}

rbac_allow if {
	some perm in input.subject.permissions
	permission_matches(perm, input.action)
}

permission_matches(perm, action) if perm == "*"
permission_matches(perm, action) if perm == concat(":", ["resources", action])
permission_matches(perm, action) if perm == "resources:read" ; action == "read"
permission_matches(perm, action) if perm == "resources:write" ; action in ["read", "write"]

# ---------------------------------------------------------------------------
# 2. ABAC Clearance & Attribute Check
# ---------------------------------------------------------------------------
clearance_allow if {
	"admin" in input.subject.roles
}

clearance_allow if {
	req_ordinal := sensitivity_ordinal[input.resource_sensitivity]
	user_ordinal := input.subject.attributes.clearance_ordinal
	user_ordinal >= req_ordinal
}

# Department-scoped ABAC rules
department_allow if {
	input.resource != "payroll-db"
	input.resource != "finance-reports"
}

department_allow if {
	input.resource in ["payroll-db", "finance-reports"]
	input.subject.attributes.department in ["Finance", "HR", "finance", "hr"]
}

department_allow if {
	"admin" in input.subject.roles
}

# ---------------------------------------------------------------------------
# 3. Contextual Trust & Risk Gating
# ---------------------------------------------------------------------------
trust_score_allow if {
	floor := sensitivity_floor[input.resource_sensitivity]
	input.trust_score >= floor
}

device_mfa_allow if {
	input.trust_score >= 80
	input.mfa_verified == true
}

device_mfa_allow if {
	input.resource_sensitivity == "PUBLIC"
}

# ---------------------------------------------------------------------------
# Final Decision Synthesis
# ---------------------------------------------------------------------------
final_allow if {
	rbac_allow
	clearance_allow
	department_allow
	trust_score_allow
	device_mfa_allow
	input.trust_score >= 40
}

reasons contains "RBAC permission check failed" if not rbac_allow
reasons contains "Role clearance below resource sensitivity ceiling" if not clearance_allow
reasons contains "Department attribute mismatch for restricted resource" if not department_allow
reasons contains "Trust score below sensitivity floor" if not trust_score_allow
reasons contains "Device not trusted or MFA required" if not device_mfa_allow
reasons contains "Trust score in critical risk band (< 40)" if input.trust_score < 40

decide_action := "ALLOW" if {
	final_allow
	input.trust_score >= 80
} else := "ALLOW_LIMITED" if {
	final_allow
	input.trust_score >= 60
} else := "STEP_UP_MFA" if {
	not final_allow
	input.trust_score >= 40
	not input.mfa_verified
} else := "BLOCK"

decision := {
	"allow": final_allow,
	"action": decide_action,
	"reasons": [r | some r in reasons],
}
