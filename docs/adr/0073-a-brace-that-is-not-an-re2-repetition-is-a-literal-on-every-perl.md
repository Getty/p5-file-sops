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

## Not covered (left standing)

- `{n,m}` with n > m and counts above 1000: RE2 refuses to compile (rule
  matches nothing), Perl compiles. Inside an alternation (`(a{2,1}|b)`) the
  two sides then select differently. Not reproduced here.
