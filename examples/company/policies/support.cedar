// Support: customers, tickets, refunds. Amounts are integers in minor units:
// 5000 = 50.00.

@id("support-read-customer")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Customer)
when { ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region };

@id("support-update-customer")
permit(principal == Agent::"support-orchestrator", action == Action::"update", resource is Customer)
when { ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region };

@id("support-read-ticket")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Ticket)
when { ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region };

@id("support-write-ticket")
permit(principal in AgentGroup::"support-agents", action in [Action::"create", Action::"update"], resource is Ticket)
when { ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region };

// Like customers and tickets: when a list of refunds is read, the engine drops
// the rows of other regions itself. The region stated with the request is only
// what the caller says the list is about.
@id("support-read-refund")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Refund)
when { ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region };

// One refund of up to 50.00 needs nobody else.
@id("support-refund-small")
permit(principal in AgentGroup::"support-agents", action == Action::"create", resource is Refund)
when {
  ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region &&
  context has spend && context.spend.amount <= 5000
};

// A larger one waits for a support supervisor. The role's budget still caps
// the total per task.
@id("support-refund-large-needs-supervisor")
@require_approval("refund-over-50")
permit(principal in AgentGroup::"support-agents", action == Action::"create", resource is Refund)
when {
  ["support-agent", "support-supervisor"].contains(context.iam.role) && resource has region &&
  context has spend && context.spend.amount > 5000
};

// Nobody refunds a customer account that is their own.
@id("no-refund-to-your-own-account")
forbid(principal, action == Action::"create", resource is Refund)
when { resource has customer_owner && resource.customer_owner == context.iam.user_id };

// ---- fields
@id("support-read-fields")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Field)
when { ["crm.customer", "crm.ticket", "billing.refund"].contains(resource.resource) };

@id("support-update-customer-contact-fields")
permit(principal == Agent::"support-orchestrator", action == Action::"update", resource is Field)
when { resource.resource == "crm.customer" && ["email", "phone", "addresses"].contains(resource.name) };

@id("support-write-ticket-fields")
permit(principal in AgentGroup::"support-agents", action in [Action::"create", Action::"update"], resource is Field)
when { resource.resource == "crm.ticket" };

@id("support-create-refund-fields")
permit(principal in AgentGroup::"support-agents", action == Action::"create", resource is Field)
when { resource.resource == "billing.refund" && resource.name != "status" };
