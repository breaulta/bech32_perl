#!/usr/bin/perl
use warnings;
use strict;

my $testcases = 'testcases.txt';
open (my $in, "<:encoding(utf8)", $testcases) or die "$testcases: $!";
my @lines = <$in>;
close $in;

my $stdout; 
chomp @lines;
for my $line (@lines) {
    #print "theline: $line\n";
    #Run bech32.pl with arguments in $line and return the standard out to $stdout.
    $stdout = qx/perl bech32.pl $line/; 
    print "$line $stdout\n";


}
