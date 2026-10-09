// Rules that hold for the whole company, whatever the unit. All are forbids:
// they can only take away what a unit's permits give. Every forbid whose scope
// is not limited to a resource type starts with `context has iam`, because
// the engine also evaluates action "approve" (a human approving a held
// request) with a context that has no `iam`, and a forbid that errors denies.

// Support and sales people work the records of their own region only.
@id("regional-roles-stay-in-their-region")
forbid(principal, action, resource)
when {
  context has iam &&
  ["support-agent", "support-supervisor", "sales-rep", "sales-manager"].contains(context.iam.role) &&
  resource has region && context.iam.user_attrs has region &&
  resource.region != context.iam.user_attrs.region
};

// An agent three steps away from the human reads; it does not change anything.
@id("third-level-agents-are-read-only")
forbid(principal, action, resource)
when {
  context has iam && context.iam.depth >= 3 &&
  action != Action::"read" && action != Action::"delegate"
};

// The auditor role looks and does not touch. The role's ceiling already says
// so (actions: read); this rule keeps it true if the ceiling is ever widened.
@id("auditor-role-is-read-only")
forbid(principal, action, resource)
when {
  context has iam && context.iam.role == "auditor" &&
  action != Action::"read" && action != Action::"delegate"
};
