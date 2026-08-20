#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Test::Pod ();
use Pod::Checker;

# karr #98 -- Test::Pod (the xt/author/pod-syntax.t that
# [PodSyntaxTests] generates at build time) checks POD SYNTAX only: it
# never resolves an L<> target, so a link to a section that does not
# exist passes it silently. That is exactly how two dead links
# (L</_deserialize_value>, L</use File::SOPS;>) sat in the tree unseen
# until someone ran podchecker by hand. Pod::Checker's "unresolved
# internal link" check is the same check podchecker(1) runs, and it
# catches that class of error. Test::Pod stays; this is additional
# coverage, not a replacement.
#
# This only means anything against WOVEN pod. =method/=attr/=opt are
# Pod::Weaver directives, not standard POD -- a L</some_method> link
# resolves only once weaving has turned the directive into a real
# =head2 under =head1 METHODS. Checking lib/ before a build gives
# nothing but noise (podchecker reports "Unknown directive: =method" on
# every one, dozens of false positives per file) -- it cannot tell a
# real dead link from a section that simply has not been woven in yet.
#
# No recursive dzil build here, and none is needed: like
# xt/author/pod-syntax.t itself, this file lives under xt/author/, so
# [ExtraTests] (already part of [@Author::GETTY]'s @Basic-derived
# plugin list, no dist.ini change needed) moves it to
# t/author-pod-links.t and adds the AUTHOR_TESTING guard at build time.
# The same `dzil build`/`dzil test` step that promotes it also weaves
# the POD in lib/ it goes on to check -- there is no second build to
# recurse into.
#
# File discovery reuses Test::Pod's own all_pod_files(), so this checks
# exactly the files xt/author/pod-syntax.t already checks: blib/ if
# `make`/`Build` has run, lib/ otherwise -- both already woven by the
# time this test can see them.

my @files = Test::Pod::all_pod_files();

plan skip_all => 'no POD files found (blib/lib)' unless @files;
plan tests => scalar @files;

for my $file (@files) {
  my $report = '';
  open my $out, '>', \$report or die "can't open in-memory filehandle: $!";
  my $errors = podchecker($file, $out, -warnings => 0);
  close $out;
  ok($errors < 1, "$file: no unresolved POD links or syntax errors")
    or diag($report);
}
