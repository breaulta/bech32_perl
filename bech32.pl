#!/usr/bin/perl
use warnings;
use strict;

# This is the set of characters used for encoding.
my @CHARSET = ('q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0','s','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l');
# Consult https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp for how the polymod function works.
my @GENERATOR = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
sub polymod {
    my $val_ref = shift;
    my @values = @{$val_ref}; # Convert the array reference $val_ref to a proper array; @values.
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
# There will be N number of h bits representing the higher ord, and N number of l bits representing the lower ord.
# So hrpExpand will return an array that looks like this: [N number of h chars], 0, [N number of l chars]
# Reference BIP173 for additional information: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki 
sub hrpExpand {
    my $hrp_str = shift;
    # Convert the human readable part string into an array of chars.
    my @human_readable_part = split(//, $hrp_str, length($hrp_str));
    my @ret;  #Initialize the return array.
    my $i; # i for index.
    # scalar here returns the number of values in the @human_readable_part array.
    for ($i = 0; $i < scalar @human_readable_part; ++$i) { 
	# >> 5 is a right bit shift of 5 places, effectively dividing by 32 (2^5). 
	# xxxxyyyy => 0000xxxx
	push @ret, ord($human_readable_part[$i]) >> 5;
    }
    # A '0' needs to be in the middle according to BIP173.
    push @ret, 0; 
    for ($i = 0; $i < scalar @human_readable_part; ++$i) {
	# yyyyxxxx => 0000xxxx
	# & 31 is a bit multiplication by 00001111, effectively zeroing out the 4 highest bits.
	push @ret, ord($human_readable_part[$i]) & 31;  # And now the low bits.
    }
    return \@ret;  # The backslash indicates that we are returning a reference to the @ret array.
}
# This sub handles one of the polymod functions. It takes the hrp string and expands it into an array.
# And then stacks that onto the passed in hex_data array.
# The combined array is then passed into the polymod function, which by bitmagic determines if the checksum is good or bad.
sub verifyChecksum {
    my $hrp_str = $_[0]; # The human readable part string.
    my $hex_data_to_checksum_ref = $_[1];  # Pass in the reference to the data array.
    # Copy the values referenced in the hex data array to the @hex_data array.
    # We need to find out if this hex_data array is precisely the segwit 'program'.
    my @hex_data_to_checksum = @{$hex_data_to_checksum_ref};  
    my $checksum_verified; # We're using this as a boolean variable. 
    my $hrp_expanded_ref = hrpExpand($hrp_str);
    my @hrp_expanded = @{$hrp_expanded_ref};
    push @hrp_expanded, @hex_data_to_checksum;  # [ hrp_exp values, hex_data values ]
    my $verified = polymod(\@hrp_expanded); 
    # Return 'true': the checksum has been verified.
    if ( $verified  == 1 ){ $checksum_verified = 1;}
    # Return 'false': the checksum failed to verify.
    else{ $checksum_verified = 0;}
    return $checksum_verified;
}

# Computes a 6 char long checksum array and returns it as an array reference.
sub createChecksum {   #Returns decimal Array of 6 values.
    my $hrp_str = $_[0];
    my $data_ref = $_[1];
    my @data = @{$data_ref};
    my $exp_ref = hrpExpand($hrp_str);  #Returns Array of hex decimals from the hrp
    my @hrp_exp = @{$exp_ref};
    $_ = hex($_) for @data; # Convert each hex value in the @data array to decimal.
    push @data, (0, 0, 0, 0, 0, 0); 
    push @hrp_exp, @data; # Combine the two arrays into @hrp_exp.
    my $mod = polymod(\@hrp_exp) ^ 1; # ^ 1 here means xor with 1.
    my @ret;
    for (my $i = 0; $i < 6; ++$i) {
	push @ret, (($mod >> 5 * (5 - $i)) & 31); # bitmagic
    }
    return \@ret;
}

# bech32 encoding doesn't care that the witness version and program are different things; it encodes them to the same output.
# Returns a bech32 encoded string.
sub encode_bech32 {
    my $hrp_input_str = $_[0];
    #the data here corresponds to hex numbers that reference the indexes of the CHARSET.
    my $versionandprogram_hex_data = $_[1];  
    # Transform $hrp_input_str string into the @hrp array.
    my @hrp = split(//, $hrp_input_str, length($hrp_input_str)); 
    # Check for an errant nibble.
    die "Cannot encode bech32. There must be an even number of hex data input chars!" unless length($versionandprogram_hex_data) % 2 == 0;
    die "Cannot encode bech32. Invalid Hexadecimal Character(s)!\n" unless $versionandprogram_hex_data =~ /^[a-f0-9]*$/i;
    # Convert input string into byte (2 chars) array.
    my @versionandprogram_hex_data = $versionandprogram_hex_data =~ /../g;
    my $chksum_ref = createChecksum($hrp_input_str, \@versionandprogram_hex_data);
    my @chksum = @{$chksum_ref};
    my @print_chksum = @{$chksum_ref};
    # Convert hex bytes into decimal values that can then be used to reference encoded bech32 chars in the CHARSET array.
    $_ = hex($_) for @versionandprogram_hex_data;
    # [ versionandprogram_hex_data ], [ chksum ]
    push @versionandprogram_hex_data, @chksum;
    push @hrp, 1; # In a proper bech32 encoding, the final '1' denotes the end of the human readable part.
    # Loop through the @versionandprogram_hex_data array.
    for (my $p = 0; $p < scalar @versionandprogram_hex_data; ++$p) {
	# Encode each value as bech32 and append it to the @hrp array.
	# [ hrp ], 1, [ bech32-encoded @versionandprogram_hex_data ]
	push @hrp, $CHARSET[$versionandprogram_hex_data[$p]];
    }
    my $encoded_bech32_str = join('', @hrp);
    return $encoded_bech32_str;
}

# This sub takes a (presumably) bech32 encoded string and decodes it to a 5 bit 'squashed' byte array.
sub decode_bech32 {
    my $bech32_encoded_string = shift;
    my @bech32_encoded = split (//, $bech32_encoded_string, length($bech32_encoded_string));
    my $p; # p for pointer?
    my $d; # d for decimal value of the decoded bech32 char.
    my $has_lowercase = 0;   #set to false
    my $has_uppercase = 0;   #set to false
    for ($p = 0; $p < scalar @bech32_encoded; ++$p) {
	#Check if the chars in @bech32_encoded are 'Basic Latin' unicode chars.
	#A good list can be found here: https://en.wikipedia.org/wiki/List_of_Unicode_characters
	die "Cannot decode bech32 string: One or more characters are improper unicode!" 
	    if (ord($bech32_encoded[$p]) < 33 || ord($bech32_encoded[$p]) > 126);
	#Set upper and/or lowercase flags.  Valid addresses must NOT be mixed case.
	if (ord($bech32_encoded[$p]) >= 97 && ord($bech32_encoded[$p]) <= 122) { $has_lowercase = 1; }
	if (ord($bech32_encoded[$p]) >= 65 && ord($bech32_encoded[$p]) <= 90) { $has_uppercase = 1; }
    }
    die "Cannot decode bech32: Address must not be mixed-case!" if ($has_lowercase && $has_uppercase);
    #Convert @bech32_encoded to lowercase
    $_ = lc for @bech32_encoded;
    #my $pos = @bech32_encoded.lastIndexOf('1');
    my $pos;
    #THIS SHOULD BE THE LAST '1'. 
    # CONFIRMED: needs to be the last '1'
    # We're trying to find the value of the $pos here.
    for ($pos = 0; $pos < scalar @bech32_encoded; $pos++){ #Broken
	# Loops through until it finds a '1'
	if ( $bech32_encoded[$pos] eq  '1' ) { last; }  
    }
    # Also #Broken
    die "Cannot decode bech32: Human Readable Part is too short!" if ($pos < 1 );
    die "Cannot decode bech32: Data + checksum is too short!" if ($pos + 7 > scalar @bech32_encoded);
    die "Cannot decode bech32: Address is too long!" if (scalar @bech32_encoded >90);

    #Copy the human readable part to @hrp
    # If the last position of the hrp is found correctly and placed into $pos,
    my @hrp;
    # This for loop will correctly place the data from @bech32_encoded into @hrp.
    for($p = 0; $p < $pos; $p++ ){
	$hrp[$p] = $bech32_encoded[$p];
    }
    my @decoded_hex_data;
    my $i;
    my $chset;
    my $bca;
    #For each of the chars in @bech32_encoded, find the hex value (index) of the bech32 char in CHARSET and save.
    for ($p = $pos + 1; $p < scalar @bech32_encoded; ++$p) {
	$d = -1;
	for ($i = 0; $i < scalar @CHARSET; $i++) {
	    if ($CHARSET[$i] eq $bech32_encoded[$p]){
		#$d = $bech32_encoded[$p];
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
    my $vfyChk = verifyChecksum($hrp_str, \@decoded_hex_data); # Passes in the decoded hex representation of the bech32 char
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
    my $acc = 0;
    my $bits = 0;
    my @ret;
    my $maxv = (1 << $tobits) - 1;
    for (my $p = 0; $p < scalar @data; ++$p) {
	my $value = hex($data[$p]);
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
    my $human_readable_part = $1; #$1 refers to group 1 of the regex above - everything until the last '1'.
    #A successful return from the decode sub guarantees some sort of bech32 address.
    my ($witness_version, $decoded_hex_data_ref) = decode($human_readable_part, $bech32_address);
    my @decoded_hex_data = @{$decoded_hex_data_ref};
    #Logic block.
    if ($witness_version == 0) {
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
my $checked_results;
my $bech32_address = $ARGV[0];
print "\n******************************Starting test for bech32.pl**********************************\n";
print "Testing check_bech32_address on address: $bech32_address\n";
$checked_results = check_bech32_address($bech32_address);
print "checked results:$checked_results\n";
print "Testing decode and encode:";
$bech32_address =~ /^(.*)1/;
my $human_readable_part = $1; #$1 refers to group 1 of the regex above - what's inside the parens
my ($witness_version, $decoded_hex_data_ref) = decode($human_readable_part, $bech32_address);
my @decoded_hex_data = @{$decoded_hex_data_ref};
my $program = join('', @decoded_hex_data);
print "Decode return:$human_readable_part, $witness_version, @decoded_hex_data\n";
my $encode_test = encode($human_readable_part, $witness_version, $program);
print "Encode return:$encode_test\n";
if ($encode_test eq $bech32_address) { print "Success for encode/decode!\n"; }
else { print "FAIL\n";}



