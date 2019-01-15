#!/usr/bin/perl
use warnings;
use strict;

#WARNING: This script won't work unless bitcoind is running.
#Install bitcoind and start running by: bitcoind -daemon

#Create new short (P2WPKH) bech32 address.
my $short_bech32_addr = qx/bitcoin-cli getnewaddress "" "bech32"/;
chomp ($short_bech32_addr); #Remove endline added by stdout.
#Create new long (P2WSH) address by creating a multisig thing.
my $long_bech32_addr = qx/bitcoin-cli addmultisigaddress 1 '["$short_bech32_addr"]' "" "bech32"/;
#Strip out the long address and print it with the short address.
$long_bech32_addr =~ m/\: \"(b([a-z0-9])+)?/i;
print "$short_bech32_addr $1\n";

