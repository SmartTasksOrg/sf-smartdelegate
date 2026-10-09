// Salary data. The forbid below reads `resource.frozen` without checking that
// it exists. When the attribute is missing the policy errors, and SmartDelegate
// denies: an erroring forbid is never ignored.

@id("compliance-read-salary")
permit(principal == Agent::"support-bot", action == Action::"read", resource is Salary)
when { context.iam.user in Group::"compliance" };

@id("frozen-salary-records")
forbid(principal, action, resource is Salary)
when { resource.frozen };
