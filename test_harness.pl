#!/usr/bin/perl
use warnings;
use strict;

#Read in all testcases to @lines from the file tcases.txt
open (my $fd, "<:encoding(utf8)", 'tcases.txt') or die "tcases.txt: $!";
my @testcases = <$fd>;
close $fd;

my $stdout; 
chomp @testcases;
# open with '>' option writes a new file and 'clobbers' the old file if one exists.
open (my $out_fd, '>', 'logfile.txt') or die "logfile.txt: $!";
for my $testcase (@testcases) {
    $stdout = qx/perl bech32.pl $testcase 2>&1/; 
    #Run bech32.pl with arguments in $testcase and return the standard out to $stdout.
    print "$testcase $stdout";
    print $out_fd "$testcase $stdout";
    #$stdout = system("perl bech32.pl $testcase 2>&1"); 

    # '0' exit status means that a 'die' error message was never activated.
    # STDERR seems to append a newline char while STDOUT does not.
}
close $out_fd;
