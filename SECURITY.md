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
