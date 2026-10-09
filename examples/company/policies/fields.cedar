// Field rules by classification label, for every unit. Fields are default
// deny: a unit's `...-fields` permit lets a field through, and these forbids
// take it away again by label. Role ceilings (roles.json, deny_labels) repeat
// most of them, so a mistake here and a mistake there must coincide to leak.

// Bank account numbers: treasury only.
@id("bank-details-treasury-only")
forbid(principal, action, resource is Field)
when { resource.labels.contains("bank") }
unless { context.iam.role == "treasury" };

// Full card numbers: nobody.
@id("card-numbers-nobody")
forbid(principal, action, resource is Field)
when { resource.labels.contains("card") };

// Salary figures: HR managers and payroll.
@id("salary-figures-hr-managers-and-payroll")
forbid(principal, action, resource is Field)
when { resource.labels.contains("salary") }
unless { ["hr-manager", "payroll-officer"].contains(context.iam.role) };

// Review ratings, review notes, emergency contacts: HR only.
@id("hr-confidential-hr-only")
forbid(principal, action, resource is Field)
when { resource.labels.contains("hr-confidential") }
unless { ["hr-partner", "hr-manager"].contains(context.iam.role) };

// Other secrets (national id, tax id, margin, MFA seed): named roles only.
@id("secret-fields-named-roles-only")
forbid(principal, action, resource is Field)
when { resource.labels.contains("secret") }
unless { ["treasury", "hr-partner", "hr-manager", "sales-manager"].contains(context.iam.role) };

// Secrets, internal notes and pricing stop at the agent the human started.
// A sub-agent (depth 2 or more) never receives them.
@id("sensitive-fields-not-for-sub-agents")
forbid(principal, action, resource is Field)
when {
  context.iam.depth > 1 &&
  (resource.labels.contains("secret") || resource.labels.contains("internal") || resource.labels.contains("pricing"))
};
