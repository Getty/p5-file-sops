#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# First, and deliberately: File::SOPS pulls this in through
# File::SOPS::Encrypted, so anywhere below here the load would be a no-op and
# could not fail. What is checked is that it stands on its own (karr #147).
use_ok('File::SOPS::Comment');

# Also first, and for the same reason: File::SOPS pulls this in through
# File::SOPS::Format::ENV, which is a format handler and so loaded eagerly,
# so below the next line this would be a no-op too (karr #153).
use_ok('File::SOPS::Metadata::Flat');

use_ok('File::SOPS');
use_ok('File::SOPS::Encrypted');
use_ok('File::SOPS::Metadata');
use_ok('File::SOPS::Backend::Age');
use_ok('File::SOPS::Format::YAML');
use_ok('File::SOPS::Format::JSON');

done_testing;
