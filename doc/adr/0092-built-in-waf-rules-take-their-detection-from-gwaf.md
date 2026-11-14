# 92. Built-in WAF rules take their detection from gwaf

Date: 2026-11-14

## Status

Accepted. `sec` drives (which requests are refused is the WAF's whole
contract); `arch` co-signs where the rule definitions live and the two tests
that keep them there.

## Context

Gateon embeds gwaf, and gwaf answers one question: is this request an attack?
Beside gwaf's core ruleset, `internal/security/waf/ruleset.go` held a hundred
rules of gateon's own, each written out in full: an operator, a target list, a
transform chain. They were carried over from the SecLang corpus when Coraza was
replaced, and they kept growing afterwards.

Nearly all of them asked gwaf's question. A pattern for a Stripe live key, the
Follina marker, a time-delay SQL function: none of that depends on anything
gateon knows that gwaf does not. Keeping it here had three costs.

1. **gwaf's calibration gate never saw it.** gwaf holds each rule to a
   false-positive ceiling for the confidence it declares, on a benign corpus.
   Gateon's rules declared a confidence and were never measured. When they were,
   two rules declared Medium matched 1.5% and 1.07% of benign requests against
   a ceiling of 1%.
2. **A fix had two homes.** The project rule is that a detection bug is fixed
   in gwaf first, released, and taken here with a version bump. A rule defined
   here could not follow that rule.
3. **The dashboard could not say what was running.** Security → Rules described
   itself as managing "Coraza SecLang rules in the database", and the hundred
   rules that were actually loaded appeared nowhere on it.

The question that started this was direct: since gateon uses gwaf, why does it
still add WAF rules? The measurement behind the answer is in the context of
gwaf's pull request. On gwaf's 20,000-request attack corpus, core alone misses
165 attacks at paranoia level 1 and 527 at level 2 that a gateon rule catches,
so the rules are not redundant and cannot simply be deleted. They are in the
wrong repository.

## Decision

**gwaf owns what is detected. Gateon owns identity and policy.**

The detection moved to two opt-in gwaf packages, `ruleset/signatures` (request
indicators) and `ruleset/leaks` (credentials and stack traces in a response,
credentials in a request). An entry in gateon's table is now one line that names
the gwaf rule and says only what gateon decides about it:

```go
{id: 1151006, from: signatures.IDText4Shell, status: 403, pl: 1, category: CategoryRCE,
    tags: []string{TagAttackRce, "cve-2022-42889"}},
```

- **`from`** names the gwaf rule. `resolveSpecs` copies its phase, targets,
  transforms, operator, severity and message at start-up, and panics if gwaf
  does not ship the rule.
- **`id`** stays the ID the rule has always had here. Threat history, stored
  exceptions and operators' muscle memory are keyed on it.
- **`pl`, `category`, `tags`, `status`, `action`** are policy: at which paranoia
  level the rule loads, which dashboard switch turns it off, and whether a match
  refuses or only records.
- **`conf`** may be set to hold a rule at the tier it has always loaded at. Two
  entries use it (1151004, 1151008): gwaf ships them as Low after measuring
  them, and loading them as Low here would have silently removed them from
  paranoia level 2. Changing a default is a decision for a release note, not a
  side effect of a refactor.

Eight rules keep their detection here, because gwaf's scope line puts them
here. Three read a decision gateon makes and hands the engine through a resolver
(reputation, admin access, origin), and the rest state what a site allows
(gambling keywords, scripted clients, how deep a request path may go) rather than what
an attack looks like.

### One rule was retired, and six that looked the same were not

Seven rules matched nothing that gwaf's core did not also match on the corpus.
Six were moved to gwaf regardless, because "core matches the same payloads" is
only true with every switch on. Core reads Log4Shell under its Java tag, a NUL
byte under path traversal, `__proto__` under Node. A route that disables the
Java rules because nothing behind it runs Java kept refusing Log4Shell through
gateon's rule 1151000, and would have stopped. The response private-key rule
(1130002) is in the set the DLP action redacts by ID, which core's own rule is
not.

Rule 1141001 (the opening of seven embedding tags) is retired. Core refuses each
of those tags once it carries an attribute, terminated or not, and both answer
to the XSS switch, so no configuration separates them. What is lost is the
refusal of the bare word `<svg` with nothing after it. It is recorded in
`Retirements` as native.

## Consequences

- **A detection fix has one home.** Change the rule in gwaf, tag it, bump the
  version here.
- **`TestNoDetectionIsDefinedInGateon`** fails when an entry writes its own
  operator and is not one of the eight. The list of eight is in the test, so
  growing it is a visible decision.
- **`TestEveryGwafBundleRuleIsLoaded`** fails when a gwaf bump brings a bundle
  rule the table does not name, so new detection cannot arrive unloaded and
  look loaded.
- **`TestRetiredAsNativeIsStillRefusedByCore`** holds the one retirement to the
  claim it was made on, with gateon's XSS rules switched off so the refusal can
  only be core's.
- **The card-number operator moved with its rule** (`leaks.CardNumber()`), so
  `operator_card.go` is gone.
- **No rule ID, category, paranoia level or action changed.** Stored exceptions
  and threat history resolve as before.
- **Security → Rules lists the built-in rules read-only**, from the same table
  the engine loads, and no longer mentions SecLang.

### What this does not fix

Five gaps in gwaf's core were found by the measurement and are detector work in
gwaf, not rule moves: `RLIKE SLEEP`, a sensitive file path in a header, a
loopback address behind URL userinfo, PHP `{${…}}`, and a shell command after a
CR/LF inside an XML body. Gateon's rules still cover each. They are listed in
gwaf's pull request.
