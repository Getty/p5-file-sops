# ADR 0074 — A number has a string half of its own only when its PV differs from the text perl writes for it

- Status: accepted
- Date: 2026-11-10
- Resolves part of k216 (perl 5.22 floor)
- Depends on ADR 0002 (the type comes from the scalar's public flags), ADR 0012
  (a scalar whose two halves disagree is refused), ADR 0015, ADR 0037
- **Moves no bytes on perl >= 5.36.** The answer of `_has_public_pv` is
  unchanged there for every scalar whose PV differs from its number's text and
  for every bare number; it changes, on every perl, only for a number carrying
  a PV equal to its own text (see Consequences).

## Context

ADR 0002 reads the PUBLIC flags (`SVf_IOK`, `SVf_NOK`, `SVf_POK`) because the
private ones are set by a mere read. `_has_public_pv` asked "is `SVf_POK`
set?" to mean "does this number state a string half of its own?", and its
comments say that merely printing a float sets only the private flag. That is
true from perl 5.36 (perldelta 5.36: stringifying an IV/NV no longer sets the
public POK). Before it, `my $s = "$n"` sets the public `SVf_POK` with the
number's own text as PV. Consequence on 5.22-5.34: a logged `+Inf` "states a
string half", `assert_representable` refuses it, and the int guard pays an
emit-and-reparse for a logged integer.

## Decision

A number has a string half of its OWN only when its PV differs from the text
this perl writes for exactly that number.

1. no public `SVf_POK`: no string half;
2. `SVf_POK` without `SVf_IOK`/`SVf_NOK` (a plain string): a string half;
3. otherwise the PV is compared with the perl text of the number, rebuilt from
   the already public flags through B: `IVX`/`UVX` for `IOK`, `NV` for `NOK`
   (`my $n = $sv->NV; "$n"`). With both flags public a match with either text
   is a trace. A PV equal to it is the trace of an output and does not count.

The PV is never numified and nothing sets a flag on the caller's scalar
(ADR 0002, k32). `Format::JSON::_wide_number` needs no change: its
IOK/NOK branches precede the plain-PV one.

## Consequences

- `dualvar(+Inf, "$n")`, `dualvar(42, "42")` and the real `"$n"` on 5.22-5.34
  behave like the bare number: same type, same bytes, MAC closes
  (`t/91-a-stringified-number-is-still-just-a-number.t`).
- `dualvar(Inf, 'banana')` and `dualvar(5, '007')` stay refused.
- Also on 5.36+: a number that carries a PV equal to its own text (a
  YAML-parsed `5432`, `dualvar(5,'5')`) is no longer "a string half". Its two
  halves agree, so it wrote the same bytes before; the int guard simply skips
  the string comparison it used to make.
- Known only from perldelta and B knowledge, not run (only 5.40 was available):
  the pre-5.36 flag behaviour of stringifying, and that `B::IV::IsUV`/`UVX`
  and `NV` read on 5.22-5.34 as they do on 5.40.

## Rejected alternatives

- Require 5.36 (rejected by the maintainer's floor decision of 5.22).
- Gate on the perl version: the same scalar built by `dualvar` has the old
  shape on a new perl; the state, not the version, is what is measured.
- Compare by numifying the PV: retypes the caller's scalar (ADR 0002, k32).

## What changes for existing callers

Nothing that worked stops working; scalars that were refused only because
they had been printed on perl < 5.36 are now written as the bare number.
