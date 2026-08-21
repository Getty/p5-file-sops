#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# First, and deliberately: File::SOPS pulls this in through
# File::SOPS::Encrypted, so anywhere below here the load would be a no-op and
# could not fail. What is checked is that it stands on its own (karr #147).
use_ok('File::SOPS::Comment');

use_ok('File::SOPS');
use_ok('File::SOPS::Encrypted');
use_ok('File::SOPS::Metadata');
use_ok('File::SOPS::Backend::Age');
use_ok('File::SOPS::Format::YAML');
use_ok('File::SOPS::Format::JSON');

done_testing;
