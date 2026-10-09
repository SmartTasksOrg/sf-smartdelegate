// IT operations: accounts, access requests, incident response.

@id("it-account")
permit(principal in AgentGroup::"it-agents", action in [Action::"read", Action::"create", Action::"update", Action::"disable"], resource is Account)
when { context.iam.role == "it-operator" };

// Password resets are limited to three per ten seconds for one operator's agent.
@id("it-reset-password")
@rate_limit("3/10")
permit(principal in AgentGroup::"it-agents", action == Action::"reset_password", resource is Account)
when { context.iam.role == "it-operator" };

@id("it-access-request")
permit(principal in AgentGroup::"it-agents", action in [Action::"read", Action::"create", Action::"update"], resource is AccessRequest)
when { context.iam.role == "it-operator" };

// Access is granted only after a manager approved the request.
@id("it-grant-standard-access")
permit(principal == Agent::"it-orchestrator", action == Action::"grant", resource is AccessRequest)
when {
  context.iam.role == "it-operator" && resource has approved_by &&
  resource has level && resource.level != "admin"
};

// Administrator access is also released by an IT manager.
@id("it-grant-admin-access-needs-it-manager")
@require_approval("privileged-access")
permit(principal == Agent::"it-orchestrator", action == Action::"grant", resource is AccessRequest)
when {
  context.iam.role == "it-operator" && resource has approved_by &&
  resource has level && resource.level == "admin"
};

@id("sod-nobody-grants-their-own-access")
forbid(principal, action == Action::"grant", resource is AccessRequest)
when { resource has employee_id && resource.employee_id == context.iam.user_id };

// Any people manager approves an access request, through the IT orchestrator,
// unless they raised it or it is for themselves.
@id("manager-approves-access-request")
permit(principal == Agent::"it-orchestrator", action in [Action::"read", Action::"approve"], resource is AccessRequest)
when { context.iam.role == "access-approver" && resource has requested_by && resource has employee_id };

@id("sod-access-approver-is-not-requester")
forbid(principal, action == Action::"approve", resource is AccessRequest)
when {
  (resource has requested_by && resource.requested_by == context.iam.user_id) ||
  (resource has employee_id && resource.employee_id == context.iam.user_id)
};

@id("it-read-employee")
permit(principal in AgentGroup::"it-agents", action == Action::"read", resource is Employee)
when { context.iam.role == "it-operator" };

// Break-glass: the incident responder, for an incident task, on accounts and
// on customer contact data.
@id("break-glass-accounts")
permit(principal == Agent::"incident-responder", action in [Action::"read", Action::"update", Action::"disable"], resource is Account)
when { context.iam.role == "break-glass" && context.iam.task like "incident-*" };

@id("break-glass-customers")
permit(principal == Agent::"incident-responder", action == Action::"read", resource is Customer)
when { context.iam.role == "break-glass" && context.iam.task like "incident-*" };

// ---- fields
@id("it-fields")
permit(principal in AgentGroup::"it-agents", action, resource is Field)
when { ["it.account", "it.access_request"].contains(resource.resource) };

@id("it-read-employee-fields")
permit(principal in AgentGroup::"it-agents", action == Action::"read", resource is Field)
when {
  resource.resource == "hr.employee" &&
  ["id", "name", "email", "unit", "region", "manager", "job_title", "start_date", "status"].contains(resource.name)
};

@id("break-glass-customer-fields")
permit(principal == Agent::"incident-responder", action == Action::"read", resource is Field)
when {
  resource.resource == "crm.customer" &&
  ["id", "name", "email", "phone", "region", "tier"].contains(resource.name)
};
