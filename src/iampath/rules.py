"""Escalation rules (Phase 2). RULE_KINDS is the single list of rule numbers (D46)."""

RULE_KINDS = {
    1: "grant",  # iam:CreatePolicyVersion
    2: "grant",  # iam:SetDefaultPolicyVersion
    3: "grant",  # iam:AttachUserPolicy
    4: "grant",  # iam:AttachGroupPolicy
    5: "grant",  # iam:AttachRolePolicy
    6: "grant",  # iam:PutUserPolicy
    7: "grant",  # iam:PutGroupPolicy
    8: "grant",  # iam:PutRolePolicy
    9: "grant",  # iam:AddUserToGroup
    10: "reach",  # iam:CreateAccessKey
    11: "reach",  # iam:CreateLoginProfile
    12: "reach",  # iam:UpdateLoginProfile
    13: "reach",  # iam:UpdateAssumeRolePolicy (+ sts:AssumeRole)
    14: "reach",  # sts:AssumeRole
    15: "reach",  # iam:PassRole + ec2:RunInstances
    16: "reach",  # iam:PassRole + lambda:CreateFunction + InvokeFunction
    17: "reach",  # iam:PassRole + lambda:CreateFunction + CreateEventSourceMapping
    18: "reach",  # lambda:UpdateFunctionCode
    19: "reach",  # iam:PassRole + cloudformation:CreateStack
    20: "reach",  # ssm:SendCommand
    21: "reach",  # iam:PassRole + ecs:RegisterTaskDefinition + RunTask
}
