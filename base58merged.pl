#!/usr/bin/perl
use warnings;
use strict;

#Code validates, decodes, and encodes bitcoin addresses.
#See examples at bottom.
#Author: Len Schulwitz + friends at http://rosettacode.org/wiki/Bitcoin/address_validation
#E-mail: My last name at gmail.com.
#AS IS CODE! USE AT YOUR OWN RISK!

#SHA-256 necessary for bitcoin address validation checksum check.
use Digest::SHA qw(sha256);
#Used for POST input and prevent DDOS
use CGI qw(:standard);
$CGI::POST_MAX = 30000;  # don't allow inputs greater than 40000
$CGI::DISABLE_UPLOADS = 1;  # no uploads

# This is the set of characters used for encoding.
my @CHARSET = ('q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0','s','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l');
#The base58 characters used by Bitcoin.
my @b58 = qw{
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
};
#Used to decode base58 encoded bitcoin addresses (i.e. standard bitcoin addresses).
my %b58 = map { $b58[$_] => $_ } 0 .. 57;
#The reverse hash, used to base58 encode addresses represented as binary decimals.
my %reverseb58 = reverse %b58;

my $address = param('address') // "EMPTY";
my $b58action = param('b58action') // "EMPTY";

print "No input!" and exit if length($address) == 0;
print "Too many characters! Try the Perl source code below." and exit if length($address) > 20000;

if ($b58action eq "validate"){
    if($address =~ /^[13]/) { #If the first char is 1 or 3, it is legacy.
	my $address_type = check_bitcoin_address($address);
    } else {
	my $address_type = check_bech32_address($address);
    }
    print "Bitcoin address is valid.  Address type: '", $address_type, "'.\n";
}
elsif ($b58action eq "decode"){ 
    if($address =~ /^[13]/) { 
	print decodebase58tohex($address);
    } else { 
	$address =~ /^(.*)1/; # Take everything before the last instance of '1'.
	my $human_readable_part = $1; # $1 holds everything inside the parens above.
	my ($witness_version, $program_ref) = decode($human_readable_part, $address);	
        my @program = @{$program_ref};
	my $program_str = join('', @program);
	print "$human_readable_part $witness_version $program_str";
    }
}
elsif ($b58action eq "encode"){
    if($address =~ /^\S+\ \S+\ \S+$/) { # \S matches non-whitespace chars.
	#Parse input: 'hrp witver program'
	my ($human_readable_part, $witness_version, $program) = split(/ /, $address);
	print encode($human_readable_part, $witness_version, $program); 
    } else {
	print encodebase58fromhex($address); 
    }
}
else{
	print "Invalid base58er action!\n";
}

my $visitors_ip_address = $ENV{'REMOTE_ADDR'};
my $current_time = scalar localtime();
open B58_RECORD, ">>../b58/b58_record.txt";
print B58_RECORD "$visitors_ip_address : $current_time : $b58action : $address\n";
close B58_RECORD;

#Encodes a base58 encoded bitcoin address from array of binary decimals.
sub base58 {
        my @binary_address_to_encode = @{$_[0]};
        die "Subroutine base58 needs binary decimal array to encode!\n" unless @binary_address_to_encode;
        #This adds slightly more processing than is necessary, but will ensure all bytes are encoded.
        my $base58_encoded_array_size = 2 * scalar @binary_address_to_encode;
        my @base58_encoded_address;
        #Counts number of leading 0's in decimal address.
        my $leading_zeroes = length $1 if join('', @binary_address_to_encode) =~ /^(0*)/;
        #Cycle through each binary decimal character, encoding to Base58.
        for my $dec_char ( @binary_address_to_encode ) {
                #Cycle through each index (i.e. base58 encoded character) of array holding base58 encoded result. 
                for (my $encoded_character_index = $base58_encoded_array_size; $encoded_character_index--; ) {
                        #See Satoshi's base58.cpp code for details.
                        $dec_char += 256 * ($base58_encoded_address[$encoded_character_index] // 0);
                        $base58_encoded_address[$encoded_character_index] = $dec_char % 58;
                        $dec_char /= 58;
                }
        }
        #Generate encoded address with extra leading ones
        my $encoded_address_with_leading_1s = join('', map { $reverseb58{$_} } @base58_encoded_address);
        #Truncate address so that the number of leading zero bytes in the binary address are equal to the number of leading ones in the base58 encoded address.
        if ($encoded_address_with_leading_1s =~ /(1{$leading_zeroes}[^1].*)/){
                #Return matching base58 encoded bitcoin address.
                return $1;
        }
        #If encoding only zero bytes...
        elsif ($encoded_address_with_leading_1s =~ /(1{$leading_zeroes})/){
                return $1;
        }
        else{
                die "Unexpected error in subroutine base58!\n";
        }
}

#Decodes bitcoin address from its Base58 encoding into an array of binary decimals.
sub unbase58 {
        my $bitcoin_address = $_[0];
        die "Subroutine unbase58 needs base58 encoded bitcoin address to decode!\n" unless defined $bitcoin_address;
        print "Cannot Decode! Invalid Base58 Character(s)!\n" and exit unless $bitcoin_address =~ /^[1-9A-HJ-NP-Za-km-z]*$/;
        #This is overkill, but it allows for plenty of room to store decoded bytes.
        my $decoded_array_size = length($bitcoin_address);
        my @decoded_binary_address; #Array that will hold bytes of Base58 decoded address.
        #Counts number of leading 1's in bitcoin address.
        my $leading_ones = length($1) if $bitcoin_address =~ /^(1*)/;
        #Cycle through each character of address, decoding from Base58.
        for my $b58_char ( map { $b58{$_} } $bitcoin_address =~ /./g ) {
                #Cycle through each index (i.e decimal byte) of array holding base58 decoded result.
                for (my $decoded_byte_index = $decoded_array_size; $decoded_byte_index--; ) {
                        #See Satoshi's base58.cpp code for encoding details.
                        $b58_char += 58 * ($decoded_binary_address[$decoded_byte_index] // 0);
                        $decoded_binary_address[$decoded_byte_index] = $b58_char % 256;
                        $b58_char /= 256;
                }
        }
        #Counts number of leading zeroes in decoded binary decimal array.
        my $leading_zeroes = length($1) if join('', @decoded_binary_address) =~ /^(0*)/;
        #If leading zeroes of decoded address don't equal leading ones of encoded address, trim them off.
        for (1 .. $leading_zeroes - $leading_ones){
                shift @decoded_binary_address;
        }
        return @decoded_binary_address;
}

#Dies if address is bad, otherwise, returns address type.
#See https://en.bitcoin.it/wiki/List_of_address_prefixes for valid address types.
sub check_bitcoin_address {
        my $base58_address = shift;
        my @decoded_binary_address = unbase58 $base58_address;
        #See if last 4 bytes of the 25-byte base58 decoded bitcoin address (i.e. the checksum) match the double sha256 hash of the first 21 bytes.
        print "Invalid bitcoin address! Address is not 25 bytes!\n" and exit if scalar @decoded_binary_address != 25;
        print "Invalid Bitcoin address! Bad SHA-256 checksum!\n" and exit unless (pack 'C*', @decoded_binary_address[21..24]) eq substr sha256(sha256 pack 'C*', @decoded_binary_address[0..20]), 0, 4;
        #Standard bitcoin address.
        if ($base58_address =~ /^1/){
                return "Standard Public";
        }
        #Multi-signature bitcoin address.
        elsif ($base58_address =~ /^3/){
                return "Multi-Signature";
        }
        #Testnet standard bitcoin address.
        elsif ($base58_address =~ /^m/ or $base58_address =~ /^n/){
                return "Testnet Public";
        }
        #Testnet multi-signature bitcoin address.
        elsif ($base58_address =~ /^2/){
                return "Testnet Multi-Signature";
        }
        #If address is valid but not a recognized type, it is abnormal.
        else{
                return "Abnormal";
        }
}

#Converts standard bitcoin address to binary form as hexadecimal.
sub decodebase58tohex {
        #Takes standard base58 encoded bitcoin address
        my $std_bitcoin_address = $_[0];
        die "Subroutine decodebase58tohex needs base58 bitcoin address as input!\n" unless (defined $std_bitcoin_address and length $std_bitcoin_address != 0);
        #Base58 decodes address to binary decimal form.
        my @decoded_binary_address = unbase58($std_bitcoin_address);
        #Converts binary to hexadecimal.
        my $hex_binary_address = '';
        foreach(@decoded_binary_address){
                $hex_binary_address .= sprintf("%02X", $_);
        }
        return $hex_binary_address;
}

#Converts binary bitcoin address input as hexadecimal to standard Base58 address.
sub encodebase58fromhex {
        #Takes hexadecimal representation of 25-byte binary address.
        my $hex_binary_address = $_[0];
        die "Subroutine encodebase58fromhex needs binary address represented with hex characters as input!" unless (defined $hex_binary_address and length $hex_binary_address != 0);
        print "Cannot Encode! Invalid Hexadecimal Character(s)!\n" and exit unless $hex_binary_address =~ /^[a-f0-9]*$/i;
        #If odd number of hex characters, let's assume that we can prepend a zero, so that we have an array of full bytes (i.e. no ambiguous hanging nibble).
        if( $hex_binary_address =~ m/^[a-f0-9]([a-f0-9][a-f0-9])*$/i ){
                $hex_binary_address = '0' . $hex_binary_address;
        }
        #Converts to binary decimal form.
        my @binary_address_to_encode = $hex_binary_address =~ /../g;
        for( 0 .. scalar(@binary_address_to_encode)-1 ){
                $binary_address_to_encode[$_] = hex($binary_address_to_encode[$_]);
        }
        #Base58 encodes and returns standard form bitcoin address.
        my $std_bitcoin_address = base58(\@binary_address_to_encode);
        return $std_bitcoin_address;
}

# Consult https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp for how the polymod function works.
my @GENERATOR = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
sub polymod {
    my $val_ref = $_[0];
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
    # 'shift' reads in the first argument passed to the sub.
    my $hrp_str = shift;
    # Convert the human readable part string into an array of chars.
    my @human_readable_part = split(//, $hrp_str, length($hrp_str));
    my @ret;  #Initialize the return array.
    my $i; # i for index.
    # scalar here returns the number of values in the @human_readable_part array.
    for ($i = 0; $i < scalar @human_readable_part; ++$i) {
        # Start with the high bits. ord() returns the numeraic value (unicode) of a char.
        # >> 5 is a right bit shift of 5 places, effectively dividing by 32 (2^5). (I don't know why it isn't *4 except for the previous sentence.)
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
    # I'm still unsure what exactly polymod does, hence, $poly
    # Although it is clear that a return of 1 verifies the checksum.
    my $poly = polymod(\@hrp_expanded);
    # Return 'true': the checksum has been verified.
    if ( $poly  == 1 ){ $checksum_verified = 1;}
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
    for (my $p = 0; $p < 6; ++$p) {
        push @ret, (($mod >> 5 * (5 - $p)) & 31); # bitmagic
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
    #print "\nEntering convertbits.\nData in the data array:";
#    foreach (@data) { print "$_ ";}
    my $acc = 0;
    my $bits = 0;
    my @ret;
    my $maxv = (1 << $tobits) - 1;
    for (my $p = 0; $p < scalar @data; ++$p) {
        my $value = hex($data[$p]);
        #print "\nvalue:$value";
#       if ($value < 0 || ($value >> $frombits) != 0) {
#           print "\nFail1\n";
#           return; #Fail condition.
#       }
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
    $bech32_address =~ /^(.*)1/; # Looks like this properly takes till the last '1'.
    my $human_readable_part = $1; #$1 refers to group 1 of the regex above - everything until the last '1'.
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

