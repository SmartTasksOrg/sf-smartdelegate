// Refunds. Amounts are integers in minor units: 10000 = 100.00 EUR.

@id("refund-small")
@rate_limit("3/60")
permit(principal in AgentGroup::"support-agents", action == Action::"create", resource is Refund)
when {
  context.iam.user in Group::"support" &&
  context has spend && context.spend.currency == "EUR" && context.spend.amount <= 10000
};

@id("refund-large-needs-approval")
@require_approval("refund-over-100-eur")
permit(principal == Agent::"support-bot", action == Action::"create", resource is Refund)
when {
  context.iam.user in Group::"support" &&
  context has spend && context.spend.currency == "EUR" &&
  context.spend.amount > 10000 && context.spend.amount <= 20000
};

@id("refund-fields")
permit(principal in AgentGroup::"support-agents", action == Action::"create", resource is Field)
when { resource.resource == "billing.refund" && !resource.labels.contains("internal") };

@id("no-refund-to-yourself")
forbid(principal, action == Action::"create", resource is Refund)
when { resource has customer_owner && resource.customer_owner == context.iam.user_id };
