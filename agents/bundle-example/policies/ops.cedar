// The two agent definitions in agents/ run under these rules. The resource
// `smartdelegate.ops/<tool>` stands for one operations tool of the MCP server
// (integrations/mcp/server.py --govern). Monitoring tools are action "read";
// privileged tools (delegate, approve, revoke_user, reload) are action
// "operate". Nothing here permits "operate": granting it is a decision for
// the adopter, written as a separate permit for a separate role.

@id("ops-delegate-operator")
permit(principal in Group::"sd-operators", action == Action::"delegate", resource == Agent::"smartdelegate-operator");

@id("ops-delegate-integrator")
permit(principal in Group::"sd-integrators", action == Action::"delegate", resource == Agent::"smartdelegate-integrator");

// Only the agent the human started, never a sub-agent of it.
@id("ops-operator-reads-monitoring")
permit(principal == Agent::"smartdelegate-operator", action == Action::"read", resource is SmartDelegateOps)
when { context.iam.role == "sd-operator" && context.iam.depth == 1 };

@id("ops-integrator-reads-status")
permit(principal == Agent::"smartdelegate-integrator", action == Action::"read", resource == SmartDelegateOps::"status")
when { context.iam.role == "sd-integrator" && context.iam.depth == 1 };

// Belt and braces: even if a later permit or a wider role ceiling appears,
// these two roles never operate a privileged tool.
@id("ops-agent-roles-never-operate")
forbid(principal, action == Action::"operate", resource is SmartDelegateOps)
when { context.iam.role == "sd-operator" || context.iam.role == "sd-integrator" };
