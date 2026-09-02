# Verifying the ENA claims on real hardware

gateon tells operators specific things about native XDP on EC2: that the ENA
driver refuses it above a page-sized MTU (~3498 on a 4 KiB page, and the EC2 VPC
default is 9001), and unless the driver is using at most half its queues. Those
numbers appear in the preflight message and in `doc/adr/0007`.

They were reasoned from driver behaviour. The `ena-verify` workflow is what
checks them against an actual instance, and it fails if the prediction and the
hardware disagree **in either direction** — a diagnosis claiming "blocked" where
XDP in fact attaches is as wrong as one that offers no reason while the attach
fails.

## Before you set this up: this repository is public

GitHub's own guidance is not to attach self-hosted runners to public
repositories, and the reason applies squarely here. A workflow triggered by
`pull_request` runs the workflow file **and the code** from the fork that opened
it. Anyone could open a pull request that runs arbitrary commands on this
instance — with its instance profile, its network position inside your VPC and
whatever it can reach.

The workflow therefore triggers on `workflow_dispatch` and `schedule` only, and
is guarded by `if: github.repository == 'gsoultan/gateon'`. **Do not add
`pull_request` to it.** `pull_request_target` is worse, not better: it runs with
the base repository's secrets.

Practical mitigations, in the order they are worth doing:

1. **Give the instance no IAM role**, or one with no permissions. The job needs
   no AWS API access — it reads the network interface, not the account.
2. **Put it in an isolated subnet** with no route to anything you care about. It
   needs outbound HTTPS to github.com and the package mirrors; nothing else.
3. **Treat it as disposable.** Terminate and recreate rather than debugging in
   place. Nothing on it is state you need.
4. Prefer an **ephemeral** runner (`--ephemeral`) so each job gets a fresh
   registration and a compromised job cannot linger.

## Instance requirements

- Any ENA-backed instance type — which is all current generations. The claims
  concern the driver, not the size, so the cheapest thing that boots is fine.
- Ubuntu or Amazon Linux with a kernel new enough for the eBPF loader. CI builds
  the BPF object on the runner, so `clang` and the libbpf headers are installed
  by the job.
- **Leave the MTU alone.** The default 9001 is the condition being tested. An
  instance with MTU already lowered to 1500 will report a different — and
  correct — verdict, which is fine, but it is not the case the claims are about.
- Passwordless `sudo` for the runner user. Attaching XDP needs `CAP_NET_ADMIN`.

## Registering the runner

From the instance, using a registration token from
**Settings → Actions → Runners → New self-hosted runner**:

```bash
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -o actions-runner.tar.gz -L \
  https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
tar xzf actions-runner.tar.gz

# Only the labels a self-hosted Linux runner has by default. There is no `ena`
# label on purpose: it would be a second place for the requirement to live and
# to drift. The test checks the driver itself and fails, rather than skipping,
# when it was asked to verify and cannot -- so a run that lands on the wrong
# machine is loud instead of quietly green.
./config.sh --url https://github.com/gsoultan/gateon \
  --token <REGISTRATION_TOKEN> \
  --labels self-hosted,linux \
  --name ena-verify-$(hostname) \
  --unattended --ephemeral

./run.sh
```

For anything beyond a one-off, run it under systemd with `./svc.sh install &&
./svc.sh start` rather than a shell that dies with your session.

## Running it

Actions → **ena-verify** → *Run workflow*, once the workflow is on the default
branch — `workflow_dispatch` only registers for workflows that exist there, which
is why pushing to a `ci/ena-*` branch also triggers it. That push trigger is safe
in a way `pull_request` is not: forks cannot push to this repository, so the code
that runs is always code someone with write access placed on a branch.

It also runs weekly, because the claims only change when the kernel, the ENA
driver or the instance type changes — none of which happen per commit.

Leave the interface input blank to autodetect `ens5`, `enX0` or `eth0`, or name
one explicitly.

## Reading the result

The **Report what this host actually is** step prints the instance type, kernel,
MTU, driver and queue counts unconditionally, so a failure can be read against
the hardware it ran on instead of guessed at.

Then the verification either agrees with the prediction or fails saying which
way it diverged:

- *"the preflight would have told an operator native XDP is unavailable … but it
  attached"* — the advice is wrong for this host and the diagnosis needs
  narrowing.
- *"native XDP was refused but the preflight found no blocker to name"* — the
  worse direction. The attach fails and gateon has nothing specific to say, so
  operators get the driver's bare errno.

A skip means the verification was not requested (`GATEON_VERIFY_ENA` unset) or
the job is not running as root. If it *was* requested and the interface turns out
not to be ENA-driven, that is a failure rather than a skip.

## A note on arm64

The MTU ceiling is derived from the running page size, not hardcoded, because it
is `page - frame overhead - XDP headroom - skb_shared_info`. On a 4 KiB-page host
that is ~3498 and an MTU of 9001 is over it; a kernel with larger pages is far
more permissive and native XDP may well attach. Both outcomes are correct, and
the test asserts the *prediction matches the host* rather than assuming either —
which is the entire reason the ceiling was never written as a constant.
