# Security

`aws-orgseed` is a portfolio/reference project demonstrating an OIDC-based,
least-privilege bootstrap pattern for multi-account AWS Organizations. It is
not a maintained production security tool, and there is no SLA on fixes.

That said, the design intent is that every role and policy in this repo be
genuinely least-privilege (see `bootstrap/org-seeding-role.yaml`'s comments
for the reasoning behind the split between `OrgSeedAdmin` and
`TerraformCI`). If you find a gap between that intent and what's actually
deployed — an overly broad statement, a missing condition, a trust policy
that's looser than it should be — please open an issue. Given this is a
public example repo rather than a hosted service, there's no private
disclosure process; a public issue is fine for anything found here.

## Known residual risk: OrgSeedAdmin can rewrite itself

`OrgSeedAdmin` must be able to update the bootstrap CloudFormation stacks, and
those stacks contain its own IAM role - so it is permitted to change its own
policy. The `TerraformCI` role is protected from self-escalation by explicit
Deny statements; `OrgSeedAdmin` is not. Anyone who can run the `seed` workflow
can therefore, in effect, administer every seeded org's management account.

The mitigations are procedural and in the workflow, not in IAM: the `seed` job
runs in the `orgseed` GitHub Environment (required reviewers, restricted to
`main`), the hub role trusts only that environment's OIDC subject, runs are
serialized, and the workflow input never reaches a shell. Treat approval of a
`seed` run as approval to administer the orgs.

A permissions boundary on `OrgSeedAdmin` would cap this in IAM, but it is
intricate (CloudFormation needs several IAM actions to manage a boundary that
must itself be immutable to the role) and can't be verified without a real org,
so it is deliberately not shipped untested. It is the natural next hardening
step - validate it in a sandbox org first.

## Known residual risk: orgseed-ci can change any customer-managed SCP

`orgseed-ci` (the role Terraform runs as) can update, delete, attach and detach
service control policies across the organization. It cannot be limited to "only
the policies orgseed created": AWS does not support tag conditions on
`UpdatePolicy`, `DeletePolicy`, `AttachPolicy` or `DetachPolicy` (only
`CreatePolicy` accepts tags; the `policy` resource type has no tag keys), so
there is no IAM condition that scopes those actions to a single policy. This was
checked against AWS's Service Authorization Reference rather than assumed.

What *is* enforced in IAM:

- **Never the organization root by default.** The root ARN is only in the role's
  `AttachPolicy`/`DetachPolicy` resources when `AllowAttachToRoot=true` is
  passed to the bootstrap stack (default `false`), so a guardrail cannot be
  attached to every member account at once by this role. The baseline stack also
  refuses a root target, but that is Terraform code; this is the IAM-level backstop.
  `prove.yml` tests it with real calls (`attach_scp_to_root`, `detach_scp_from_root`).
- **No self-escalation** - explicit denies on the role's own policy and on `OrgSeedAdmin`.
- Organizations writes only to the SCP/OU/root ARN patterns; nothing in member accounts.

What is *not*: the role can still detach or edit an SCP that something else in the
org relies on. The compensating controls are the two-approval workflow (a human
reads the plan, then approves the apply), CloudTrail records for every call, and
the state-file diff. Treat approval of a `terraform` run as approval to change any
customer-managed SCP.
