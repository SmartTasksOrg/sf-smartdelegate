// HR: employee records, salaries, performance reviews.

@id("hr-employee")
permit(principal in AgentGroup::"hr-agents", action in [Action::"read", Action::"create", Action::"update"], resource is Employee)
when { ["hr-partner", "hr-manager"].contains(context.iam.role) };

@id("hr-review")
permit(principal in AgentGroup::"hr-agents", action in [Action::"read", Action::"create", Action::"update"], resource is Review)
when { ["hr-partner", "hr-manager"].contains(context.iam.role) };

@id("hr-salary")
permit(principal in AgentGroup::"hr-agents", action in [Action::"read", Action::"create", Action::"update"], resource is Salary)
when { context.iam.role == "hr-manager" };

// HR raises the access request for a new hire; IT acts on it.
@id("hr-raise-access-request")
permit(principal in AgentGroup::"hr-agents", action in [Action::"read", Action::"create"], resource is AccessRequest)
when { ["hr-partner", "hr-manager"].contains(context.iam.role) };

// ---- fields
@id("hr-fields")
permit(principal in AgentGroup::"hr-agents", action in [Action::"read", Action::"create", Action::"update"], resource is Field)
when { ["hr.employee", "hr.salary", "hr.review", "it.access_request"].contains(resource.resource) };
