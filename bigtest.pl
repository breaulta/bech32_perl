#!/usr/bin/perl
use warnings;
use strict;

my $testcases = 'testtestcases.txt';
open (my $in, "<:encoding(utf8)", $testcases) or die "$testcases: $!";
my @lines = <$in>;
close $in;

my $stdout;; 
chomp @lines;
for my $line (@lines) {
    #print "theline: $line\n";
    $stdout = qx/perl bech32.pl $line/; 
    print "stdout:$stdout\n";


}
