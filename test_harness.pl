#!/usr/bin/perl
use warnings;
use strict;

#Read in all testcases to @lines from the file tcases.txt
open (my $fd, "<:encoding(utf8)", 'tcases.txt') or die "tcases.txt: $!";
my @testcases = <$fd>;
close $fd;

my $stdout; 
chomp @testcases;
for my $testcase (@testcases) {
    #Run bech32.pl with arguments in $testcase and return the standard out to $stdout.
    print "$testcase ";
    $stdout = system("perl bech32.pl $testcase"); 
    # '0' exit status means that a 'die' error message was never activated.
    # STDERR seems to append a newline char while STDOUT does not.
    if ($stdout == 0) {print "\n";} 
}
