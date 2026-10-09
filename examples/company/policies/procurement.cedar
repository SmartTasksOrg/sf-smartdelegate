// Procurement: purchase orders and vendors.

@id("buyer-purchase-order")
permit(principal in AgentGroup::"procurement-agents", action in [Action::"read", Action::"create", Action::"update"], resource is PurchaseOrder)
when { context.iam.role == "buyer" };

// Any employee can raise a requisition through the procurement orchestrator.
@id("requisitioner-purchase-order")
permit(principal == Agent::"procurement-orchestrator", action in [Action::"read", Action::"create"], resource is PurchaseOrder)
when { context.iam.role == "requisitioner" };

@id("po-approver-reads-purchase-order")
permit(principal in AgentGroup::"procurement-agents", action == Action::"read", resource is PurchaseOrder)
when { context.iam.role == "po-approver" };

@id("po-approver-reads-vendor")
permit(principal in AgentGroup::"procurement-agents", action == Action::"read", resource is Vendor)
when { context.iam.role == "po-approver" };

// An approval names who raised the order. Without that, nothing is approved.
@id("po-approver-approves")
permit(principal == Agent::"procurement-orchestrator", action == Action::"approve", resource is PurchaseOrder)
when { context.iam.role == "po-approver" && resource has requested_by };

@id("sod-po-approver-is-not-requester")
forbid(principal, action == Action::"approve", resource is PurchaseOrder)
when { resource has requested_by && resource.requested_by == context.iam.user_id };

@id("buyer-vendor")
permit(principal in AgentGroup::"procurement-agents", action in [Action::"read", Action::"create", Action::"update"], resource is Vendor)
when { context.iam.role == "buyer" };

// A vendor is activated by a procurement manager who did not onboard it.
@id("po-approver-activates-vendor")
permit(principal == Agent::"procurement-orchestrator", action == Action::"approve", resource is Vendor)
when { context.iam.role == "po-approver" && resource has onboarded_by };

@id("sod-vendor-activator-is-not-onboarder")
forbid(principal, action == Action::"approve", resource is Vendor)
when { resource has onboarded_by && resource.onboarded_by == context.iam.user_id };

// ---- fields
@id("procurement-read-fields")
permit(principal in AgentGroup::"procurement-agents", action == Action::"read", resource is Field)
when { ["procurement.po", "procurement.vendor"].contains(resource.resource) };

@id("procurement-write-po-fields")
permit(principal in AgentGroup::"procurement-agents", action in [Action::"create", Action::"update"], resource is Field)
when { resource.resource == "procurement.po" && resource.name != "approved_by" };

@id("procurement-approve-fields")
permit(principal == Agent::"procurement-orchestrator", action == Action::"approve", resource is Field)
when {
  (resource.resource == "procurement.po" && ["id", "status", "approved_by"].contains(resource.name)) ||
  (resource.resource == "procurement.vendor" && ["id", "status"].contains(resource.name))
};

@id("procurement-create-vendor-fields")
permit(principal in AgentGroup::"procurement-agents", action == Action::"create", resource is Field)
when {
  resource.resource == "procurement.vendor" &&
  ["id", "name", "region", "status", "contact_email", "onboarded_by"].contains(resource.name)
};

@id("procurement-update-vendor-fields")
permit(principal in AgentGroup::"procurement-agents", action == Action::"update", resource is Field)
when {
  resource.resource == "procurement.vendor" &&
  ["name", "region", "contact_email"].contains(resource.name)
};
