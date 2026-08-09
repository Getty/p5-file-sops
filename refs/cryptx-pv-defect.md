# CryptX PV non-NUL-termination — upstream report draft

Status: **draft, awaiting maintainer sign-off before sending to
bug-CryptX@rt.cpan.org** (CPAN-RT; CryptX does not maintain a GitHub issues
list, so this is the canonical issue channel for the distribution).

Target: maintainer of CryptX (Karel Miko, CPAN id MIK).
Affected versions: at least 0.087; behaviour not yet verified on 0.090
(released 2026-06-17).

---

## Subject

[gcm_decrypt_verify] Returned plaintext SV is not NUL-terminated at SvCUR;
perl's numeric conversion reads past the buffer

## Body

CryptX's AES-GCM `gcm_decrypt_verify` returns the plaintext as a Perl SV whose
PV buffer is not NUL-terminated at SvCUR. This is a silent data-corruption
hazard for any caller that treats the return value as a number.

Reproduction:

    use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
    use Crypt::PRNG;

    my $key  = Crypt::PRNG::random_bytes(32);
    my $iv   = Crypt::PRNG::random_bytes(12);
    my $aad  = '';
    my $pt   = '100000000000000000000';   # 1e20 — past the 64-bit UV range

    my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, $aad, $pt);
    my $got        = gcm_decrypt_verify('AES', $key, $iv, $aad, $ct, $tag);

    # $got is the string '100000000000000000000' BUT:
    print length($got), "\n";   # 21 — correct
    print "$got\n";             # '100000000000000000000' — correct
    print 0+$got, "\n";         # SOMETIMES 1e+21 instead of 1e+20

The numeric conversion depends on the byte at SvPVX + SvCUR. When that byte
happens to be a digit, perl's Atof reads past the buffer and produces a
different number. Probability depends on the allocator; in our suite it shows
up on roughly one leaf in a hundred when the plaintext is a wide integer or
any float. The bug does not require the plaintext to be numeric — it only
needs to be read as a number after decryption.

The same problem appears for *any* float, because floats always go through
Atof in sv_2nv. It only spares integers that fit in a UV.

## Workaround we use today

`return "$plaintext"` instead of `return $plaintext`. The stringify goes
through sv_setpvn, which allocates a fresh buffer perl terminates itself.
This belongs at the decrypt boundary, not at every numeric conversion site,
because every conversion site is a new place to forget it.

## Suggested fix

In `gcm_decrypt_verify`, hand the plaintext back as a Perl scalar via
`sv_setpvn` (or equivalent) rather than relying on the XS to leave the buffer
in a Perl-readable state. The function claims to return a Perl scalar; the
scalar should respect the Perl scalar contract.

A secondary suggestion: if there is a reason to avoid the copy, document the
hazard explicitly in the POD with the workaround above.

## How we found it

File::SOPS is a pure-Perl implementation of Mozilla SOPS (Secrets OPerationS).
We call `gcm_decrypt_verify` to recover the plaintext bytes of a leaf that
was AES-GCM-encrypted under a SOPS data key. The downstream code then runs
the bytes through perl's type-coercion to a number whenever the leaf's
declared SOPS type is `int` or `float`. Some encrypted integers (specifically
those above 2^64, encoded as the JSON-string-form Go produces) came back
with their last digit duplicated roughly one time in a hundred. The
regression test (`t/18-decrypt-determinism.t`) runs the same plaintext
through `decrypt_bytes` 200 times and asserts the result is identical every
time — without the workaround it fails intermittently.

The trigger is `SvPVX + SvCUR` not pointing at `\0`. We are not asking for a
specific implementation, only for the buffer to either be terminated or
for the function to communicate the length to perl by the documented
mechanism (`sv_setpvn` / `sv_setpvn_fresh` / similar).

## Environment

- Perl 5.x (reproduced on the project's CI Perl; the bug is independent of
  the perl version because the precondition — NUL at SvPVX + SvCUR — is
  about the CryptX XS, not perl).
- CryptX 0.087 (the version pinned by our cpanfile at the time of writing).
  0.090 is the latest released version as of filing; we have not yet
  verified whether the bug still reproduces there.