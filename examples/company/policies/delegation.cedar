// Who may start which agent, which agent may hand work to which sub-agent,
// and who may approve a held request. Token issuance and token exchange both
// ask for action "delegate" on the receiving Agent; a human approving a held
// request asks for action "approve" on the Agent that made it.

// ---- humans start their own unit's orchestrator, in a role of that unit
@id("no-delegation-without-a-role")
forbid(principal is User, action == Action::"delegate", resource)
when { context.iam.role == "" };

@id("support-starts-its-orchestrator")
permit(principal in Group::"support", action == Action::"delegate", resource == Agent::"support-orchestrator")
when { ["support-agent", "support-supervisor"].contains(context.iam.role) };

@id("finance-starts-its-orchestrator")
permit(principal in Group::"finance", action == Action::"delegate", resource == Agent::"finance-orchestrator")
when { ["ap-clerk", "ap-manager", "controller", "treasury", "payroll-officer"].contains(context.iam.role) };

@id("hr-starts-its-orchestrator")
permit(principal in Group::"hr", action == Action::"delegate", resource == Agent::"hr-orchestrator")
when { ["hr-partner", "hr-manager"].contains(context.iam.role) };

@id("sales-starts-its-orchestrator")
permit(principal in Group::"sales", action == Action::"delegate", resource == Agent::"sales-orchestrator")
when { ["sales-rep", "sales-manager"].contains(context.iam.role) };

@id("procurement-starts-its-orchestrator")
permit(principal in Group::"procurement", action == Action::"delegate", resource == Agent::"procurement-orchestrator")
when { ["buyer", "po-approver"].contains(context.iam.role) };

@id("it-starts-its-orchestrator")
permit(principal in Group::"it-ops", action == Action::"delegate", resource == Agent::"it-orchestrator")
when { context.iam.role == "it-operator" };

@id("compliance-starts-its-orchestrator")
permit(principal in Group::"compliance", action == Action::"delegate", resource == Agent::"compliance-orchestrator")
when { context.iam.role == "auditor" };

// ---- two roles cross unit lines, each through the owning unit's orchestrator
@id("employees-raise-requisitions")
permit(principal in Group::"employees", action == Action::"delegate", resource == Agent::"procurement-orchestrator")
when { context.iam.role == "requisitioner" };

@id("managers-approve-access-requests")
permit(principal in Group::"managers", action == Action::"delegate", resource == Agent::"it-orchestrator")
when { context.iam.role == "access-approver" };

// ---- break-glass: one person, one agent, never passed on
@id("break-glass-starts-incident-responder")
permit(principal == User::"bruno", action == Action::"delegate", resource == Agent::"incident-responder")
when { context.iam.role == "break-glass" };

@id("break-glass-is-not-passed-on")
forbid(principal is Agent, action == Action::"delegate", resource)
when { context.iam.role == "break-glass" };

// ---- an orchestrator hands work to the specialists of its own unit
@id("support-orchestrator-to-specialists")
permit(principal == Agent::"support-orchestrator", action == Action::"delegate", resource in AgentGroup::"support-agents")
when { resource != principal };

@id("finance-orchestrator-to-specialists")
permit(principal == Agent::"finance-orchestrator", action == Action::"delegate", resource in AgentGroup::"finance-agents")
when { resource != principal };

@id("hr-orchestrator-to-specialists")
permit(principal == Agent::"hr-orchestrator", action == Action::"delegate", resource in AgentGroup::"hr-agents")
when { resource != principal };

@id("sales-orchestrator-to-specialists")
permit(principal == Agent::"sales-orchestrator", action == Action::"delegate", resource in AgentGroup::"sales-agents")
when { resource != principal };

@id("procurement-orchestrator-to-specialists")
permit(principal == Agent::"procurement-orchestrator", action == Action::"delegate", resource in AgentGroup::"procurement-agents")
when { resource != principal };

@id("it-orchestrator-to-specialists")
permit(principal == Agent::"it-orchestrator", action == Action::"delegate", resource in AgentGroup::"it-agents")
when { resource != principal };

@id("compliance-orchestrator-to-specialists")
permit(principal == Agent::"compliance-orchestrator", action == Action::"delegate", resource in AgentGroup::"compliance-agents")
when { resource != principal };

// ---- two specialists have a helper of their own (the third level)
@id("contract-summarizer-to-clause-extractor")
permit(principal == Agent::"contract-summarizer", action == Action::"delegate", resource == Agent::"clause-extractor");

@id("audit-sampler-to-evidence-collector")
permit(principal == Agent::"audit-sampler", action == Action::"delegate", resource == Agent::"evidence-collector");

@id("no-long-lived-sub-agents")
forbid(principal is Agent, action == Action::"delegate", resource)
when { context.requested.ttl > 900 };

// ---- who may approve a held request
@id("supervisors-approve-refunds")
permit(principal in Group::"support-supervisors", action == Action::"approve", resource in AgentGroup::"support-agents")
when { context has label && context.label == "refund-over-50" };

@id("finance-approvers-release-payments")
permit(principal in Group::"finance-approvers", action == Action::"approve", resource in AgentGroup::"finance-agents")
when { context has label && ["payment-over-1000", "payroll-run", "period-close"].contains(context.label) };

@id("it-managers-release-admin-access")
permit(principal in Group::"it-managers", action == Action::"approve", resource in AgentGroup::"it-agents")
when { context has label && context.label == "privileged-access" };
