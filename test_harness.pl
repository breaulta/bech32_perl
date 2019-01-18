#!/usr/bin/perl
use warnings;
use strict;

#Read in all testcases to @testcases from the file tcases.txt
open (my $fd, "<:encoding(utf8)", 'tcases.txt') or die "tcases.txt: $!";
my @testcases = <$fd>;
close $fd;

my $stdout; 
chomp @testcases;
# open with '>' option writes a new file and 'clobbers' the old file if one exists.
open (my $out_fd, '>', 'logfile.txt') or die "logfile.txt: $!";
# Test check_bech32_address and 
for my $testcase (@testcases) {
    # qx// is equivalent to backticks which returns STDOUT. '2>&1' sends STDERR to STDOUT.
    $stdout = qx/perl bech32.pl $testcase 2>&1/; 
    print $stdout;
    print $out_fd $stdout; # Prints to logfile.
}
close $out_fd;
