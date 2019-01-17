#!/usr/bin/perl
use warnings;
use strict;

# This is the set of characters used for encoding.
my @CHARSET = ('q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0','s','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l');
# Consult https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp for how the polymod function works.
my @GENERATOR = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
sub polymod {
    my $val_ref = $_[0];
    my @values = @{$val_ref};
    my $chk = 1;
    for (my $p = 0; $p < scalar @values; ++$p) {
	my $top = $chk >> 25;
	$chk = ($chk & 0x1ffffff) << 5 ^ $values[$p];
	for (my $i = 0; $i < 5; ++$i) {
	    if (($top >> $i) & 1) {
		$chk ^= $GENERATOR[$i];
	    }
	}
    }
    return $chk;
}

# Expand a human readable part for use in checksum computation.
sub hrpExpand {
    # 'shift' reads in the first argument passed to the sub.
    my $hrp_str = shift;
    # Convert the human readable part string into an array of chars.
    my @human_readable_part = split(//, $hrp_str, length($hrp_str));
    my @ret;  #Initialize the return array.
    my $i; # i for index.
    for ($i = 0; $i < scalar @human_readable_part; ++$i) { # scalar here returns the number of values in the @hrp array.
	push @ret, ord($human_readable_part[$i]) >> 5;  # Start with the high bits. ord() returns the unicode of a char.
    }
    push @ret, 0;
    for ($i = 0; $i < scalar @human_readable_part; ++$i) {
	push @ret, ord($human_readable_part[$i]) & 31;  # And now the low bits.
    }
    return \@ret;  # The backslash indicates that we are returning a reference to the @ret array.
}

sub verifyChecksum {
    my $hrp_str = $_[0];
    my $data_to_checksum_ref = $_[1];  # Pass in the reference to the data array.
    my @data_to_checksum = @{$data_to_checksum_ref};  # Copy the values referenced in the data array to the @data array.
    my $return_flag; # We're using this as a boolean variable.
    my $hrp_expanded_ref = hrpExpand($hrp_str);
    my @hrp_expanded = @{$hrp_expanded_ref};
    push @hrp_expanded, @data_to_checksum;  # [ hrp_exp values, data values ]
    my $poly = polymod(\@hrp_expanded); # I need a better variable name here.
    if ( $poly  == 1 ){
	$return_flag = 1;
    }else{
	$return_flag= 0;
    }
    return $return_flag;
}

sub createChecksum {   #Returns decimal Array of 6 values.
    my $hrp_str = $_[0];
    my $data_ref = $_[1];
    my @data = @{$data_ref};
    my $exp_ref = hrpExpand($hrp_str);  #Returns Array of hex decimals from the hrp
    my @hrp_exp = @{$exp_ref};
    $_ = hex($_) for @data; # Convert each hex value in the @data array to decimal.
    push @data, (0, 0, 0, 0, 0, 0); 
    push @hrp_exp, @data; # Combine the two arrays into @hrp_exp.
    my $mod = polymod(\@hrp_exp) ^ 1; # xor with 1.
    my @ret;
    for (my $p = 0; $p < 6; ++$p) {
	push @ret, (($mod >> 5 * (5 - $p)) & 31); # bitmagic
    }
    return \@ret;
}

sub encode_bech32 {
    my $hrp_input_str = $_[0];
    my $hex_data_input_str = $_[1];  #the data here corresponds to numbers that reference the indexes of the CHARSET
    my @hrp = split(//, $hrp_input_str, length($hrp_input_str));
    die "Cannot encode bech32. There must be an even number of hex data input chars!" unless length($hex_data_input_str) % 2 == 0;
    die "Cannot encode bech32. Invalid Hexadecimal Character(s)!\n" unless $hex_data_input_str =~ /^[a-f0-9]*$/i;
    #convert input string into byte array
    my @hex_data = $hex_data_input_str =~ /../g;
    #convert to lower case to satisfy perl's disdain for uppercase
    my $chksum_ref = createChecksum($hrp_input_str, \@hex_data);
    my @chksum = @{$chksum_ref};
    my @print_chksum = @{$chksum_ref};
#    print "\nComputed Checksum: ";
    foreach (@print_chksum){ 
	$_ = hex($_);
	print "$_ ";
    }
    $_ = hex($_) for @hex_data;
    push @hex_data, @chksum;
    push @hrp, 1; #should be bc1 (or tc1 for the testnet) now, and we're going to append the dereferenced char array
    for (my $p = 0; $p < scalar @hex_data; ++$p) {
    #looks like we're decoding indexes of CHARSET from @data into their respective chars for an encode
	push @hrp, $CHARSET[$hex_data[$p]];
    }
    my $ret_str = join('', @hrp);
    return $ret_str;
}

sub decode_bech32 {
    my $bechString = $_[0];
    #convert string to array
    my @bechArr = split (//, $bechString, length($bechString));
    my $p;
    my $d;
    my $has_lowercase = 0;   #set to false
    my $has_uppercase = 0;   #set to false
    for ($p = 0; $p < scalar @bechArr; ++$p) {
	#Check if the chars are 'Basic Latin' unicode chars.
	#A good list can be found here: https://en.wikipedia.org/wiki/List_of_Unicode_characters
	die "Cannot decode bech32 string: One or more characters are improper unicode!" 
	    if (ord($bechArr[$p]) < 33 || ord($bechArr[$p]) > 126);
	#Set upper and/or lowercase flags.  Valid addresses must NOT be mixed case.
	if (ord($bechArr[$p]) >= 97 && ord($bechArr[$p]) <= 122) { $has_lowercase = 1; }
	if (ord($bechArr[$p]) >= 65 && ord($bechArr[$p]) <= 90) { $has_uppercase = 1; }
    }
    die "Cannot decode bech32: Address must not be mixed-case!" if ($has_lowercase && $has_uppercase);
    #Convert @bechArr to lowercase
    $_ = lc for @bechArr;
    #my $pos = @bechArr.lastIndexOf('1');
    my $pos;
    #Find the first '1' in order to determine the human readable part.
    for ($pos = 0; $pos < scalar @bechArr; $pos++){
	if ( $bechArr[$pos] eq  '1' ) { last; }  
    }
    #my $var = $pos + 7;
    #check if the human readable part and full string aren't too long
    #if ($pos < 1 || $pos + 7 > scalar @bechArr || scalar @bechArr > 90)
    die "Cannot decode bech32: Human Readable Part is too short!" if ($pos < 1 );
    die "Cannot decode bech32: Data + checksum is too short!" if ($pos + 7 > scalar @bechArr);
    die "Cannot decode bech32: Address is too long!" if (scalar @bechArr >90);

    #my @hrp = @bechArr.substring(0, $pos);
    #Copy the human readable part to @hrp
    my @hrp;
    for($p = 0; $p < $pos; $p++ ){
	$hrp[$p] = $bechArr[$p];
    }
    my @decoded_hex_data;
    my $i;
    my $chset;
    my $bca;
    #For each of the chars in @bechArr, find the hex value (index) of the bech32 char in CHARSET and save.
    for ($p = $pos + 1; $p < scalar @bechArr; ++$p) {
	$d = -1;
	for ($i = 0; $i < scalar @CHARSET; $i++) {
	    if ($CHARSET[$i] eq $bechArr[$p]){
		#$d = $bechArr[$p];
		#d is the index of the char in CHARSET and also the value in hex.
		$d = $i;
		last;
	    }
	}
	#Can't find the bech32 char!
	die "Cannot decode bech32: Invalid bech32 character detected!" if ($d eq '-1');
	push @decoded_hex_data, $d;
    }

    my $hrp_str = join('', @hrp);
    my $vfyChk = verifyChecksum($hrp_str, \@decoded_hex_data);
    die "Cannot decode bech32: Invalid checksum!" if (!$vfyChk);
    my @data_ret;
    for ($p = 0; $p < scalar @decoded_hex_data - 6; $p++){
	$data_ret[$p] = $decoded_hex_data[$p];
    }
    #Convert the values in the return array to 2 digit hex values.
    foreach (@data_ret){ $_ = sprintf("%.2x", $_); }
    return ($hrp_str, \@data_ret);
}
#data is an array with the preceeding char (witness version) removed
#frombits and tobits are ints
#pad is a boolean
#function convertbits (data, frombits, tobits, pad) {
sub convertbits {
    my $data_ref = $_[0];
    my $frombits = $_[1];
    my $tobits = $_[2];
    my $pad_bool = $_[3];
    my $test;

    my @data = @{$data_ref};
    #print "\nEntering convertbits.\nData in the data array:";
#    foreach (@data) { print "$_ ";}
    my $acc = 0;
    my $bits = 0;
    my @ret;
    my $maxv = (1 << $tobits) - 1;
    for (my $p = 0; $p < scalar @data; ++$p) {
	my $value = hex($data[$p]);
	#print "\nvalue:$value";
#	if ($value < 0 || ($value >> $frombits) != 0) {
#	    print "\nFail1\n";
#	    return; #Fail condition.
#	}
	die "Cannot convert bits from negative values!" if ($value < 0);
	die "Cannot convert bits.  One or more values in the data array are too big!" if (($value >> $frombits) != 0);
	$acc = ($acc << $frombits) | $value;
	$bits += $frombits;
	while ($bits >= $tobits) {
	    $bits -= $tobits;
	    push @ret, (($acc >> $bits) & $maxv);
	}
    }
    if ($pad_bool) {
	if ($bits > 0) {
	    push @ret, (($acc << ($tobits - $bits)) & $maxv);
	}
    } elsif ($bits >= $frombits || (($acc << ($tobits - $bits)) & $maxv)) {
	#$test = (($acc << ($tobits - $bits)) & $maxv);
	#print "\ntest:$test";
	#print "\nbits:$bits frombits:$frombits acc:$acc tobits:$tobits maxv:$maxv\n";
	#return;  #Fail condition. 
	die "Cannot convert bits! The bitmagic failed somehow.";
    }
    # Convert back to hex.
    foreach (@ret){ $_ = sprintf("%.2x", $_); }
    return \@ret;
}

# Segwit address decode.
sub decode {
    my $hrp = $_[0];
    my $addr = $_[1];

    #  my dec = bech32.decode(addr);
    my ($hrp_string, $data_ref) = decode_bech32($addr);
    my @data = @{$data_ref};

    #die "Cannot decode Segwit address. Decoded human readable part is inequivalent to the input hrp!" if ($hrp_string ne $hrp);
    die "Cannot decode Segwit address. The program (data) seems to be empty!" if (scalar @data < 1);
    die "Cannot decode Segwit address. Witness versions above 16 are not specified!" if ($data[0] > 16);

    #removes the first element of array.  In this case, the witness version.
    my $witness_version = shift @data; 
    #Convert from 5 sig bits to 8 sig bits.
    my $program_ref = convertbits(\@data, 5, 8, 0);
    my @program = @{$program_ref};

    die "Cannot decode Segwit address. The program (data) is empty!" if (scalar @program == 0);
    die "Cannot decode Segwit address. The program (data) is too short!" if (scalar @program < 2);
    die "Cannot decode Segwit address. The program (data) is too long!" if (scalar @program > 40);
    #This check is recommended by BIP173.
    die "Cannot decode. Segwit addresses with witness version '0' must be either 20 or 32 bytes long!" 
	if ($witness_version == 0 && scalar @program != 20 && scalar @program != 32);

    return ($witness_version, \@program);
}

# I believe this is a segwit address encode. Version is the witness version,
# and program is the data. The witver does live inside the data!
# function encode (hrp, version, program) {
sub encode {
    my $hrp = $_[0];
    my $version = $_[1];
    my $program_str = $_[2];  #presumably a hex string
    #convert input string into byte array 
    my @program = $program_str=~ /../g;

    #Convert from 8 sig bits to 5 sig bits.
    my $converted_program_ref = convertbits(\@program, 8, 5, 1);
    my @conv_prog = @{$converted_program_ref};
    my $converted = join('', @conv_prog);
    my $ver_and_prog = $version . $converted;
    my $encoded = encode_bech32($hrp, $ver_and_prog);

    #Test if encoded properly. 
    my ($test_witver, $test_prog_ref) = decode($hrp, $encoded);
    die "Segwit encode failed. This error message should never be reached!" if not defined $test_witver; 
    return $encoded;
}

#Dies if the address is bad, otherwise returns the type of bech32 address.
sub check_bech32_address {
    my $bech32_address = shift;
    #Match all the characters before the last '1'.
    $bech32_address =~ /^(.*)1/;
    my $human_readable_part = $1; #$1 refers to group 1 of the regex above - what's inside the parens
    #A successful return from the decode sub guarantees some sort of bech32 address."
    my ($witness_version, $decoded_hex_data_ref) = decode($human_readable_part, $bech32_address);
    my @decoded_hex_data = @{$decoded_hex_data_ref};
    #Logic block.
    if ($witness_version == 0) {
	#die "test eval";
	#print "test eval";
	#Mainnet bech32 address.
	if ($bech32_address=~ /^bc1/i){
	    #Mainnet Pay to Witness Private Key Hash
	    if ( scalar @decoded_hex_data == 20 ){
		return "Mainnet P2WPKH";
	    #Mainnet Pay to Witness Script Hash
	    }elsif( scalar @decoded_hex_data == 32){
		return "Mainnet P2WSH";
	    #This line should be unreachable. Something went wrong.
	    }else{ return "This addreess length is invalid for witness version '00'!";}
	}   
	#Testnet bech32 address.
	elsif ($bech32_address =~ /^tb1/i){
	    #Testnet Pay to Witness Private Key Hash
	    if ( scalar @decoded_hex_data == 20 ){
		return "Testnet P2WPKH";
	    #Testnet Pay to Witness Script Hash
	    }elsif( scalar @decoded_hex_data == 32){
		return "Testnet P2WSH";
	    #Something went wrong.
	    }else{ return "This addreess length is invalid for witness version '00'!";}
	}else{
	    return "Unknown human readable part!";
	} 
    }else{
	return "Valid bech32, but the witness version '$witness_version' is unspecified for the current release of bitcoin.";
    }
}



my $i = 0;
my $stdout;
foreach (@ARGV) {
    #eval { check_bech32_address($_) }; warn $@ if $@;


    $stdout = check_bech32_address($_);
    print "$stdout\n";
}

    #6 tests
    #

    # Sub to write when everything is working and it's time to integrate into the schulwitz base58 site.
    #sub handle_input_from_website {
#}
=begin comment
# Test cases from https://github.com/sipa/bech32/blob/master/ref/c%2B%2B/tests.cpp
my @testcases = ('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx', 'BC1SW50QA3JX3S', 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj', 'bc1qcpwqjl9yzw33puu4hnuhvj5kmv9t5evmkde2rf');

# Other testcases
my $bech32_encoded_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
#my $bech32_encoded_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
#my $bech32_encoded_address = "A12UEL5L";
#my $bech32_encoded_address = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs";
#my $bech32_encoded_address = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
#my $bech32_encoded_address = "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j";
#my $bech32_encoded_address = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w";
#my $bech32_encoded_address = "?1ezyfcl";
print "\nRunning tests for bech32 address $bech32_encoded_address\n";
my ($hrp_string, $data_ref) = decode_bech32($bech32_encoded_address);
my @out_data = @{$data_ref};
print "\nThe bech32 decode output:\nhuman readable part(hrp): $hrp_string\nData in base 32 hex: ";
foreach (@out_data){ print "$_"; }
my $data_to_encode = join('', @out_data);
my $reencoded_bech32 = encode_bech32($hrp_string, $data_to_encode);
print "\nRe-encoded back to bech32 is: $reencoded_bech32";
print "\nOriginal bech32 address     : $bech32_encoded_address\n\n";


# SegWit tests
#foreach (@testcases) {
#    print "\n*****************************************************************************************************";
#    # Decoder test
#    my $test_hrp = "tyler";
#    print "\nRunning test for bitconverter using $_\n";
#    my ($wit_ver, $program_ref) = decode($test_hrp, $_);
#    my @program_ = @{$program_ref};
#    print "\nWitness version: ~$wit_ver~\nProgram: ";
#    foreach (@program_) { print "$_"; }
#    print "\n";
#
#    # Encoder test
#    my $program_test_str = join('', @program_);
#    print "\nRunning Segmented Witness test for encode.";
#    print "\nhrp:$test_hrp witver:$wit_ver program:$program_test_str";
#    my $encoded_test = encode($test_hrp, $wit_ver, $program_test_str);
#    print "\nEncoded test result should match decode input:$encoded_test\n";
#
#}
my $test_hrp = "bc";
my $wit_ver = '00';
my $program_test_str = "751e76e8199196d454941c45d1b3a323f1433bd6";
print "\n*****************************************************************************************************";
print "\nRunning Segmented Witness test for encode.";
print "\nhrp:$test_hrp witver:$wit_ver program:$program_test_str";
my $encoded_test = encode($test_hrp, $wit_ver, $program_test_str);
print "\nEncoded test result:$encoded_test Running a decode test on the result...";
my ($wit_ver, $program_ref) = decode($test_hrp, $encoded_test);
my @prog = @{$program_ref};
print "\nWitness version: ~$wit_ver~\nProgram: ";
foreach (@prog) { print "$_"; }
print "\n";



print "\n*****************************************************************************************************";
print "\n*****************************************************************************************************";
#my $test_bech32_address_check = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"; #invalid length
#my $test_bech32_address_check = "BC1SW50QA3JX3S";  #invalid, too short
#my $test_bech32_address_check = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";  #valid p2wpkh
#my $test_bech32_address_check = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";  #valid P2WSH
print "\nRunning bech32 address check on address:$test_bech32_address_check";
print "\nThe bech32 address decodes as:", check_bech32_address($test_bech32_address_check),"\n";

=end comment
=cut

