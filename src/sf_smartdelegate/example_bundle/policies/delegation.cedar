// Who may hand authority to which agent. Token issuance and token exchange
// both ask for action "delegate" on the receiving Agent.

@id("delegate-support-users")
permit(principal in Group::"support", action == Action::"delegate", resource == Agent::"support-bot");

@id("delegate-compliance")
permit(principal in Group::"compliance", action == Action::"delegate", resource == Agent::"support-bot");

@id("delegate-support-bot-helpers")
permit(principal == Agent::"support-bot", action == Action::"delegate", resource)
when { [Agent::"refund-helper", Agent::"summarizer"].contains(resource) };

@id("delegate-helper-chain")
permit(principal == Agent::"refund-helper", action == Action::"delegate", resource == Agent::"summarizer");

@id("no-long-lived-subagents")
forbid(principal is Agent, action == Action::"delegate", resource)
when { context.requested.ttl > 600 };

// Who may approve a held request.
@id("supervisors-approve")
permit(principal in Group::"supervisors", action == Action::"approve", resource is Agent);
