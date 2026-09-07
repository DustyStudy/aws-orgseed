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
