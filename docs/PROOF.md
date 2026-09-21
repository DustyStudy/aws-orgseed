# Proof that aws-orgseed works

Everything here was run for real against a real AWS Organization and real GitHub
Actions, on **2026-09-21**, then checked against AWS's own records (CloudTrail, S3,
Organizations) rather than only against the tool's own output. Account IDs, the state
bucket and the OU ID are omitted; they were masked in every log (0 occurrences across all
runs).

The point is not that it worked first time - it didn't, and [section 4](#4-what-running-it-for-real-found)
lists what broke. The point is that each claim below has evidence a reader can check and
a way to reproduce it.

## What was tested

| | |
|---|---|
| **Org** | One AWS Organization: a management account, a member account hosting the hub role, and a dedicated test account in a throwaway OU |
| **Hub** | `orgseed-hub` in the member account (reusing that account's existing GitHub OIDC provider) |
| **Repo** | `DustyStudy/aws-orgseed` - GitHub Environment `orgseed` with a required reviewer; every run below paused for a human approval |
| **Method** | Real workflow runs; CloudTrail and S3 read afterwards; IAM policy simulator used to *predict* before spending an approval |

## 1. Claims and evidence

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | The bootstrap deploys and re-applying it is a no-op | **Proven** | [seed run](https://github.com/DustyStudy/aws-orgseed/actions/runs/35660026645): both stacks reported `no changes` after assuming `OrgSeedAdmin` |
| 2 | Only the approved GitHub environment can reach AWS | **Proven for the allowed path** | CloudTrail: every `AssumeRoleWithWebIdentity` into the hub carries exactly `repo:DustyStudy@<owner-id>/aws-orgseed@<repo-id>:environment:orgseed`, no errors ([`cloudtrail-chain.json`](proof/cloudtrail-chain.json)). *A token from another repo/branch being refused was not tested - see section 5.* |
| 3 | No long-lived AWS credentials anywhere | **Proven** | Workflows authenticate by OIDC only; the repo and its Environment hold config, ARN, ExternalId and plan-key secrets - no AWS access key is stored in either |
| 4 | The hub -> org chain works, with the per-org ExternalId and the tag condition | **Proven** | CloudTrail in the management account: `AssumeRole` into `OrgSeedAdmin` and `orgseed-ci`, `externalId` supplied, no errors, 4 seconds after the hub assumption |
| 5 | Guardrails apply and roll back through CI, gated by two approvals | **Proven** | [plan](https://github.com/DustyStudy/aws-orgseed/actions/runs/35664306580) -> [apply](https://github.com/DustyStudy/aws-orgseed/actions/runs/35664635188) -> [destroy](https://github.com/DustyStudy/aws-orgseed/actions/runs/35665098417). CloudTrail: `CreatePolicy`, `AttachPolicy`, `DetachPolicy`, `DeletePolicy` were made by `assumed-role/orgseed-ci/orgseed-terraform`. Afterwards the org held only `FullAWSAccess` |
| 6 | The SCP actually enforces | **Proven** | Same six calls in the test account, SCP on vs off - see 2 |
| 7 | `orgseed-ci` cannot escalate or stray | **Proven with real calls** | [run](https://github.com/DustyStudy/aws-orgseed/actions/runs/35667177431): 17 verdicts as designed - see 3 |
| 8 | The plan handed between jobs is encrypted | **Proven** | The artifact had the OpenSSL `Salted__` header, was not gzip, contained no readable identifier or keyword, entropy 7.98 bits/byte, 24-hour retention |
| 9 | Logs leak nothing | **Proven (after fixes)** | 0 occurrences of any account ID, the bucket or the OU ID in every run's log since the fixes in section 4 |
| 10 | S3-native state locking works and the lock is released | **Proven** | State bucket version history: `terraform.tfstate.tflock` created 22:48:20, delete marker 22:48:22 - the lock the `orgseed-ci` role now can release |

## 2. The SCP enforces (before / during / after)

The same six calls, in the test account, in every phase - so the only variable is the SCP.
Nothing is created: EC2 launches are dry runs, and the CloudTrail/Config calls target
things that do not exist. Only an `AccessDenied` that **names a service control policy**
counts as enforcement; a denial for any other reason is reported separately and fails.

| Call | Role | Before | SCP attached | After destroy |
|---|---|---|---|---|
| launch, IMDSv1 allowed | guardrail | authorized | **denied by SCP** | authorized |
| launch, IMDSv2 required | control | authorized | authorized | authorized |
| launch, no options, IMDSv2-default image | control | *not measured* | authorized | authorized |
| launch, no options, IMDSv1-default image | guardrail | *not measured* | **denied by SCP** | authorized |
| `cloudtrail:StopLogging` | guardrail | authorized | **denied by SCP** | authorized |
| `config:StopConfigurationRecorder` | guardrail | authorized | **denied by SCP** | authorized |

Evidence: [`enforcement-with-scp.json`](proof/enforcement-with-scp.json),
[`enforcement-after-destroy.json`](proof/enforcement-after-destroy.json). The "before"
column was measured ad hoc, before the script existed, for the four calls that existed
then; the two implicit-launch probes were added afterwards, so for them the evidence is the
"after destroy" column against the "SCP attached" one. The before/after toggle is what shows
the SCP - not a missing permission or a typo - was the cause.

Worth knowing: a launch that sets *no* metadata options is judged by what the **image**
defaults to. An IMDSv2-by-default image (Amazon Linux 2023) is allowed - the instance *is*
IMDSv2 - and an image that defaults to IMDSv1 is denied. I expected the implicit case might
slip through; it doesn't, and it is now asserted rather than assumed.

## 3. `orgseed-ci` cannot escalate or stray (real calls)

Run **as** `orgseed-ci` through the real chain (`prove.yml`), never from an admin
session - from one, every call would succeed and the proof would mean nothing. Every call
expected to be denied is **harmless if wrongly allowed** (nonexistent policy ARNs,
deliberately malformed documents, nonexistent stacks), and a test enforces that.

| Group | Must get | Calls | Result |
|---|---|---|---|
| Self-escalation | an **explicit** deny in an identity-based policy | edit its own permissions (delete/detach/put), attach to or rewrite the trust of `OrgSeedAdmin`, update/delete the bootstrap stacks | 7 of 7 `denied_explicit` |
| Outside its remit | no policy allows it | read EC2, list IAM users, change the state bucket's policy, delete an OU, move an account | 6 of 6 denied (4 implicit, 2 terse) |
| Controls | works | `whoami`, read the org, list SCPs, read its state bucket | 4 of 4 authorized |

The explicit deny is the point of the self-escalation group: it stays closed even if the
role's allow statements are later broadened. A merely *implicit* denial would fail the
check.

**Corroborated from AWS's side.** The Organizations API tells the *caller* only "no
permission", so the two Organizations probes read as `denied_generic`; CloudTrail records
IAM's own reason for the calls of that run ([`cloudtrail-denials.json`](proof/cloudtrail-denials.json)):
*explicit deny in an identity-based policy* for the IAM and CloudFormation calls, and *no
identity-based policy allows* for the rest - including both Organizations calls. Eleven of
the twelve queried calls were indexed when this was written; the twelfth
(`DetachRolePolicy`) was not, and rests on the workflow's own verdict.

Before the first run, the IAM policy simulator was asked what the *deployed* role answers
for each probe, and all 16 simulatable probes matched its prediction. The live run then
disagreed on one - S3 answers "no such bucket" before it checks permissions, which the
simulator can't model (section 4). That is why the simulator is a prediction and the live run
is the proof.

## 4. What running it for real found

None of these was caught by cfn-lint, Checkov, tfsec, tflint, ruff, bandit, gitleaks,
actionlint, or the mocked tests - which all passed before each one surfaced. That is the
argument for running a thing like this against the real services.

| Found | By | Fixed |
|---|---|---|
| The hub trust matched the classic `repo:owner/repo` subject; GitHub emits `repo:owner@id/repo@id`, so **the hub role could never be assumed** | Reading how the owner's other repos already wrote it, then GitHub's API | #14 |
| S3-native lock release needed `s3:DeleteObject` on `*.tflock` | Review, then confirmed working by the lock's create/delete in section 1 | #12 |
| Organizations writes were pinned to the stack's region; they are served from us-east-1 | Review; confirmed by `CreatePolicy` succeeding as `orgseed-ci` | #12 |
| The per-org ExternalId secret was only a commented-out example line | First real seed run | #15 |
| The org config, kept in a *variable*, was printed in the clear in a **public** log (GitHub masks secrets, not variables) | Reading that run's log | #15 |
| The hub role ARN, a variable, printed in a step's `with:` block | Same log | #15 |
| Chaining hub -> `orgseed-ci` needed `sts:TagSession` (the credentials action tags sessions by default); widening the trust was the wrong fix | First terraform run | #17 |
| **A failing proof went green**: GitHub's default shell has no `pipefail`, so `python \| tee` swallowed the exit status; the run printed `RESULT: FAIL` and succeeded | The least-privilege run's output disagreeing with its own status | #20 |
| Two probes were wrong, not the role: the Organizations API gives the caller less than IAM logs, and S3 answers "no such bucket" before it checks permissions | CloudTrail's own error text | #20 |
| A destroy's summary said "Applied" | Reading the destroy run | #18 |

Cleanup that mattered: the first seed run's log exposed the identifiers, so that run was
deleted (deleting only its logs did not take effect; deleting the run did).

## 5. What this does not prove

- **A token from another repo or branch being refused.** The allowed path is proven; the
  denial path rests on the trust policy's text and the Environment's branch restriction, and
  was not attacked.
- **`OrgSeedAdmin` cannot rewrite itself** - it can, it has to manage its own stack. That is
  a documented residual risk (see `SECURITY.md`); the mitigation is the approval gate, not IAM.
  A permissions boundary would cap it and is deliberately not shipped untested.
- **The human approval is a human control.** The runs show jobs waiting for review and
  proceeding after it; a script can't prove a person read the plan.
- **One org, one hub.** The hub-and-spoke claim across several orgs was not exercised, nor
  was **GovCloud**.
- **The CloudTrail baseline and Identity Center** were not applied (they need resources that
  do not exist here); only the SCP was.
- **The SCP's exemption for `orgseed-ci`** was not exercised: that role lives in the
  management account, where SCPs never apply.
- **One test account.** Enforcement is shown in one account of one org.
- The guardrail SCP was applied only to a throwaway OU containing only an empty test
  account, and removed. Nothing here says it is safe to attach to your real workloads - trial
  it the same way first.

## 6. Reproduce it

Prerequisites: an AWS Organization; a hub account; a test member account in a throwaway OU;
this repo with an `orgseed` GitHub Environment (required reviewer, `main` only) and the
secrets in the README quickstart (`ORGSEED_CONFIG`, `ORGSEED_HUB_ROLE_ARN`,
`ORGSEED_TRUST_<ALIAS>`, `ORGSEED_PLAN_KEY`).

1. **Bootstrap:** deploy `bootstrap/oidc-provider.yaml` in the hub (check the `sub` format
   first: `gh api repos/<owner>/<repo>/actions/oidc/customization/sub`), run
   `python cli/seed.py --init <alias>` in the management account, then run the **seed**
   workflow. Expect `no changes`.
2. **Before:** `python cli/prove_enforcement.py --account <test> --role <role> --phase no-scp`
3. **Apply:** run **terraform** with `action=apply`; approve the plan, read it, approve the apply.
4. **During:** `... --phase with-scp --wait 120` - expect the four guardrail calls denied by the SCP.
5. **Least privilege:** run **prove**. Expect 17 verdicts and a green job (a disagreement now
   turns it red).
6. **Roll back:** run **terraform** with `action=destroy`, then `... --phase no-scp --wait 120`.
7. **Read AWS's side:** CloudTrail event history for `CreatePolicy`, `AttachPolicy`,
   `DetachPolicy`, `DeletePolicy`, and `AssumeRole` into `orgseed-ci`.

`docs/proof/` holds the machine-readable evidence from the runs above.
