// Finance: invoices, payments, the ledger, payroll payments, vendor bank
// details. Amounts are integers in minor units: 100000 = 1,000.00.

// ---- accounts payable
@id("ap-read-invoice")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Invoice)
when { ["ap-clerk", "ap-manager", "treasury"].contains(context.iam.role) };

@id("ap-update-invoice")
permit(principal in AgentGroup::"finance-agents", action == Action::"update", resource is Invoice)
when { ["ap-clerk", "ap-manager"].contains(context.iam.role) };

@id("ap-read-purchase-order")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is PurchaseOrder)
when { ["ap-clerk", "ap-manager"].contains(context.iam.role) };

@id("ap-read-vendor")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Vendor)
when { ["ap-clerk", "ap-manager", "treasury"].contains(context.iam.role) };

@id("ap-read-refund")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Refund)
when { ["ap-clerk", "ap-manager"].contains(context.iam.role) };

@id("ap-update-refund")
permit(principal == Agent::"finance-orchestrator", action == Action::"update", resource is Refund)
when { ["ap-clerk", "ap-manager"].contains(context.iam.role) };

@id("ap-read-payment")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Payment)
when { ["ap-clerk", "ap-manager", "treasury"].contains(context.iam.role) };

// A payment names who asked for the money and who approved that. Without
// both, nothing is paid. Up to 1,000.00 needs nobody else.
@id("ap-pay-small")
permit(principal in AgentGroup::"finance-agents", action == Action::"create", resource is Payment)
when {
  [Agent::"finance-orchestrator", Agent::"payment-poster"].contains(principal) &&
  ["ap-clerk", "ap-manager"].contains(context.iam.role) &&
  resource has kind && ["po", "refund"].contains(resource.kind) &&
  resource has requested_by && resource has approved_by &&
  context has spend && context.spend.amount <= 100000
};

// Above 1,000.00 a finance approver must release it.
@id("ap-pay-large-needs-finance-approver")
@require_approval("payment-over-1000")
permit(principal in AgentGroup::"finance-agents", action == Action::"create", resource is Payment)
when {
  [Agent::"finance-orchestrator", Agent::"payment-poster"].contains(principal) &&
  ["ap-clerk", "ap-manager"].contains(context.iam.role) &&
  resource has kind && ["po", "refund"].contains(resource.kind) &&
  resource has requested_by && resource has approved_by &&
  context has spend && context.spend.amount > 100000
};

// Separation of duties: whoever asked for the money does not pay it,
// whoever approved it does not pay it, and nobody approves their own request.
@id("sod-payer-is-not-requester")
forbid(principal, action == Action::"create", resource is Payment)
when { resource has requested_by && resource.requested_by == context.iam.user_id };

@id("sod-payer-is-not-approver")
forbid(principal, action == Action::"create", resource is Payment)
when { resource has approved_by && resource.approved_by == context.iam.user_id };

@id("sod-payment-needs-independent-approval")
forbid(principal, action == Action::"create", resource is Payment)
when { resource has requested_by && resource has approved_by && resource.requested_by == resource.approved_by };

// ---- payroll
@id("payroll-read-employee")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Employee)
when { context.iam.role == "payroll-officer" };

@id("payroll-read-salary")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Salary)
when { context.iam.role == "payroll-officer" };

// Every payroll payment is released by a finance approver.
@id("payroll-pay-needs-finance-approver")
@require_approval("payroll-run")
permit(principal == Agent::"finance-orchestrator", action == Action::"create", resource is Payment)
when {
  context.iam.role == "payroll-officer" &&
  resource has kind && resource.kind == "payroll" && context has spend
};

// ---- the ledger
@id("controller-read-ledger")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is LedgerEntry)
when { context.iam.role == "controller" };

@id("controller-post-entry")
permit(principal in AgentGroup::"finance-agents", action == Action::"create", resource is LedgerEntry)
when { context.iam.role == "controller" && resource has period_open && resource.period_open };

@id("controller-approve-entry")
permit(principal == Agent::"finance-orchestrator", action == Action::"approve", resource is LedgerEntry)
when { context.iam.role == "controller" && resource has posted_by };

@id("sod-entry-approver-is-not-poster")
forbid(principal, action == Action::"approve", resource is LedgerEntry)
when { resource has posted_by && resource.posted_by == context.iam.user_id };

@id("controller-close-period-needs-finance-approver")
@require_approval("period-close")
permit(principal == Agent::"finance-orchestrator", action == Action::"close", resource is LedgerEntry)
when { context.iam.role == "controller" };

// ---- treasury
@id("treasury-update-vendor-bank")
permit(principal == Agent::"finance-orchestrator", action == Action::"update", resource is Vendor)
when { context.iam.role == "treasury" };

// ---- fields
@id("finance-read-fields")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Field)
when {
  ["billing.invoice", "billing.refund", "finance.payment", "finance.ledger",
   "procurement.po", "procurement.vendor", "hr.salary"].contains(resource.resource)
};

@id("payroll-read-employee-fields")
permit(principal in AgentGroup::"finance-agents", action == Action::"read", resource is Field)
when {
  resource.resource == "hr.employee" &&
  ["id", "name", "unit", "region", "status", "start_date", "job_title", "bank_account"].contains(resource.name)
};

@id("finance-write-fields")
permit(principal in AgentGroup::"finance-agents", action in [Action::"create", Action::"update", Action::"approve", Action::"close"], resource is Field)
when {
  ["finance.payment", "finance.ledger"].contains(resource.resource) ||
  (resource.resource == "billing.invoice" && ["status", "po_id"].contains(resource.name)) ||
  (resource.resource == "billing.refund" && resource.name == "status")
};

@id("treasury-write-vendor-bank-fields")
permit(principal == Agent::"finance-orchestrator", action == Action::"update", resource is Field)
when {
  context.iam.role == "treasury" && resource.resource == "procurement.vendor" &&
  ["bank.iban", "bank.bic"].contains(resource.name)
};
