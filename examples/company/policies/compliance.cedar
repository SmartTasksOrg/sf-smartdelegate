// Compliance: the auditor role reads every resource of every unit. What it
// never sees (card numbers, bank accounts, other secrets, salaries, review
// notes) is removed by the role ceiling and by fields.cedar.

@id("auditor-reads-every-resource")
permit(principal in AgentGroup::"compliance-agents", action == Action::"read", resource)
when { context.iam.role == "auditor" && !(resource is Field) };

@id("auditor-reads-fields")
permit(principal in AgentGroup::"compliance-agents", action == Action::"read", resource is Field)
when { context.iam.role == "auditor" };
