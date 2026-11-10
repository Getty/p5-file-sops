# ADR 0073 — A brace that is not an RE2 repetition is a literal on every perl

- Status: accepted
- Date: 2026-11-10
- Resolves part of k216 (perl 5.22 floor)
- Depends on ADR 0048 (rules are matched in RE2's dialect), ADR 0051
  (read/write split of the refusal)
- **Moves no bytes.** Only which keys a rule selects changes, and only for
  patterns carrying a non-repeat brace.

## Context

Go/RE2 reads `{` as a repetition only when it is `{n}`, `{n,}` or `{n,m}`.
Everything else is a literal brace. Perl does not agree with itself across
versions: `a{,3}` is a literal on 5.22-5.28, a fatal error on 5.30-5.32 and
the quantifier `{0,3}` from 5.34. With a 5.22 floor the same rule would
select different keys depending on the perl.

## Measurement (sops 3.13.3, `--unencrypted-regex`, key plain = rule matched)

| pattern | matches (literal key) | does not match |
|---|---|---|
| `^a{,3}$` | `a{,3}` | `aa`, `a`, empty |
| `^a{,}$` | `a{,}` | `a`, `aa`, empty |
| `^a{ 1,3}$`, `^a{1, 3}$` | the literal | `a`, `aa` |
| `^a{a}$`, `^a{-1}$` | the literal | `a` |
| `^a{1$`, `^a{1,$`, `^a{$` | the literal | `a` |
| `^a{01}$`, `^a{1,03}$` | the literal (leading zero) | `a`, `aa` |
| `^a{,3}+$` | `a{,3}}`, `a{,3}` (`+` repeats the `}`) | |
| `^a{1,3}$`, `^a{0,3}$`, `^a{0}$`, `^a{3,}$` | repetition, as in Perl | |
| `^x{2,1}$` | nothing (compile error, matches nothing) | |
| `^a{1001}$` | nothing (compile error) | |
| `^{3}$` | empty key (`^` repeated) | `{3}` |

## Decision

`Metadata::_re2_perl_pattern` rewrites every unescaped `{` outside a
character class that does not open `\{(0|[1-9]\d*)(,(|0|[1-9]\d*))?\}` to
`\{`; the braces of `\x{..}`, `\p{..}`, `\P{..}` are left alone. It is the
single place: `_rule_verdict` (both rule paths of the encryption rules) and
the `path_regex` match in `creation_rules_for` both compile its output. The
possessive-quantifier scan uses the same repetition pattern, so `a{01}+` is
no longer called possessive.

## Repetition bounds RE2 refuses (k216, measured 2026-11-10, sops 3.13.3)

`--unencrypted-regex`, a plain key = the rule matched; "nothing" = RE2 cannot
compile it, every value encrypted. `--encrypted-regex` is the mirror: for
`^a{1001}$`, `^a{2,1}$`, `^(a|b{1001})$` and `^(a{501}){2}$` every value stays
plaintext; `^a{1000}$` selects only the 1000-character key.

| pattern | result |
|---|---|
| `^a{1000}$`, `^a{1000,1000}$`, `^a{1000,}$`, `^a{1,1000}$`, `^a{1,1}$` | repetition (1000 is the last good count) |
| `^(ab){1000}$`, `^[a]{1000}$`, `^.{1000,}$`, `^(a\|b){1000}$` | repetition |
| `^a{1001}$`, `^a{1001,}$`, `^a{1,1001}$`, `^a{0,1001}$`, `^a{1001,2000}$` | nothing |
| `^(ab){1001}$`, `^[a]{1001}$`, `^.{1001,}$`, `^(a*){1001}$`, `^a{1001}?$` | nothing |
| `^a{2147483648}$`, `^a{99999999999}$` | nothing |
| `^a{2,1}$`, `^a{1000,999}$`, `^a{2,1}?$`, `^(a{2,1}){0}$` | nothing |
| `^(a{2,1}\|b)$`, `^(a\|b{2,1})$`, `^(a\|b{1001})$`, `^a{2,1}\|a` | nothing: the whole pattern fails, also for the branch that was not the match |
| `^(a{100}){10}$`, `^(a{500}){2,}$`, `^(a{1000}){1,}$`, `^(a{1000})*$` | repetition (product 1000; `*` `+` `?` do not multiply) |
| `^(a{100}){11}$`, `^(a{501}){2}$`, `^(a{1000}){2}$`, `^(a{501}){0,2}$`, `^((a{100}){10}){2}$`, `^(a{1000}){2,}$`, `^(a{600}\|b){2}$` | nothing: nested product above 1000 (max, or min when open) |
| `^(a{1000}){0}b$` | repetition: a bound of 0 ends the check below it |
| `^(a{1001}){0}$` | nothing: the count itself is checked at parse |

The rule is Go's `repeatIsValid`: every `{n,m}` count is at most 1000, n is
not above m, and along any path the product of nested `{n,m}` bounds is at
most 1000.

### Decision

`Metadata::_re2_divergent_construct` reports all three as kind `unsupported`:
the read path gets `$MATCHES_NOTHING` (as sops does), the write path
refuses (ADR 0051). The scan tracks group nesting to form the product. This
matters in one direction: Perl compiles `a{1001}` and would match, so an
`unencrypted_regex` of that form would have left plaintext where sops
encrypts everything.

## Not covered (left standing)

- Double repetition (`a**`, `a{2}{3}`, `a{2}*`, `a*{2}`, `a{2}??`) is a
  compile error in RE2 as well (measured: matches nothing; `a+?` and `a{2}?`
  are fine). Perl compiles or rejects these on its own terms; not handled by
  the scanner here (ticket proposed).
