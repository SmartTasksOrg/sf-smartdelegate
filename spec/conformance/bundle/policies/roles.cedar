// Role-aware rules. `context.iam.role` is the role the human lent the agent
// for this task; it is "" when the token names none. What a role may carry at
// most is in roles.json; these policies decide what it may do with it.

@id("auditor-role-is-read-only")
forbid(principal, action, resource)
when { context has iam && context.iam.role == "auditor" && action != Action::"read" && action != Action::"delegate" };

@id("supervisor-role-large-refund")
permit(principal == Agent::"support-bot", action == Action::"create", resource is Refund)
when {
  context.iam.role == "supervisor" &&
  context has spend && context.spend.currency == "EUR" &&
  context.spend.amount > 20000 && context.spend.amount <= 50000
};
