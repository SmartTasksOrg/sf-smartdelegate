// Customer records. Resource-level permits decide whether the call happens;
// permits on `Field` decide which fields survive. Fields are default deny.

@id("support-read-customer")
@row_filter("region == context.iam.user_attrs.region")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Customer)
when { context.iam.user in Group::"support" };

@id("support-read-customer-fields")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Field)
when {
  resource.resource == "crm.customer" &&
  !resource.labels.contains("secret") &&
  !resource.labels.contains("internal")
};

@id("compliance-read-customer")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Customer)
when { context.iam.user in Group::"compliance" };

@id("compliance-read-customer-fields")
permit(principal in AgentGroup::"support-agents", action == Action::"read", resource is Field)
when { resource.resource == "crm.customer" && context.iam.user in Group::"compliance" };

// Secret fields: only for a compliance user, and only for the agent the user
// started directly, never for a sub-agent.
@id("secret-fields-compliance-only")
forbid(principal, action, resource is Field)
when { resource.labels.contains("secret") }
unless { context.iam.user in Group::"compliance" && context.iam.depth == 1 };

@id("support-update-customer")
permit(principal == Agent::"support-bot", action == Action::"update", resource is Customer)
when { context.iam.user in Group::"support" };

@id("support-update-contact-fields")
permit(principal == Agent::"support-bot", action == Action::"update", resource is Field)
when { resource.resource == "crm.customer" && ["email", "phone"].contains(resource.name) };
