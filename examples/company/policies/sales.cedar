// Sales: opportunities, contracts, and a limited view of customers.

// Reads carry a row filter: whatever region a request states, the rows of
// other regions are dropped from what comes back.
@id("sales-read-opportunity")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"sales-agents", action == Action::"read", resource is Opportunity)
when { ["sales-rep", "sales-manager"].contains(context.iam.role) && resource has region };

@id("sales-write-opportunity")
permit(principal in AgentGroup::"sales-agents", action in [Action::"create", Action::"update"], resource is Opportunity)
when { ["sales-rep", "sales-manager"].contains(context.iam.role) && resource has region };

@id("sales-read-contract")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"sales-agents", action == Action::"read", resource is Contract)
when { ["sales-rep", "sales-manager"].contains(context.iam.role) && resource has region };

@id("sales-update-contract")
permit(principal == Agent::"sales-orchestrator", action == Action::"update", resource is Contract)
when { ["sales-rep", "sales-manager"].contains(context.iam.role) && resource has region };

@id("sales-read-customer")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"sales-agents", action == Action::"read", resource is Customer)
when { ["sales-rep", "sales-manager"].contains(context.iam.role) && resource has region };

// A sales manager approves a discount on a deal that someone else owns.
@id("sales-manager-approves-discount")
permit(principal == Agent::"sales-orchestrator", action == Action::"approve", resource is Opportunity)
when { context.iam.role == "sales-manager" && resource has region && resource has owner };

@id("sod-discount-approver-is-not-owner")
forbid(principal, action == Action::"approve", resource is Opportunity)
when { resource has owner && resource.owner == context.iam.user_id };

// ---- fields
@id("sales-read-fields")
permit(principal in AgentGroup::"sales-agents", action == Action::"read", resource is Field)
when {
  ["sales.opportunity", "sales.contract"].contains(resource.resource) ||
  (resource.resource == "crm.customer" && !resource.labels.contains("internal") && !resource.labels.contains("financial"))
};

@id("sales-write-fields")
permit(principal in AgentGroup::"sales-agents", action in [Action::"create", Action::"update", Action::"approve"], resource is Field)
when {
  resource.resource == "sales.opportunity" ||
  (resource.resource == "sales.contract" && ["status", "term_months", "clauses"].contains(resource.name))
};
