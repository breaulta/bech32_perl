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

# The set of characters used in bech32 encoding.
my @CHARSET = ('q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0','s','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l');
# These numbers are used in the bech32 polymod function.
my @GENERATOR = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);
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
	#Bech32 check.
	my $bech32_check_return;
	if ($base58_address =~ /^bc/i || $base58_address =~ /^tb/i){  # Probably bech32.
	    # The eval loop catches 'die' conditions, which indicate an invalid bech32 address.
	    eval { $bech32_check_return = check_bech32_address($base58_address)};
	    if ($@){
		    return "INVALID BECH32";
		} else {   # Valid bech32 address.
		    return "BECH32:$bech32_check_return";
	    }
	}
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

# Bech32 functionality.
#Dies if the address is bad, otherwise returns the type of bech32 address.
sub check_bech32_address {
    my $bech32_address = shift;
    #Match all the characters before the last '1'.
    $bech32_address =~ /^(.*)1/;
    my $human_readable_part = $1; #$1 refers to group 1 of the regex above - everything until the last '1'.
    #A successful return from the decode sub guarantees some sort of bech32 address.
    #Otherwise, it will die.
    my ($witness_version, $decoded_hex_data_ref) = decode_segwit_address($human_readable_part, $bech32_address);
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

# Segwit address decode.
sub decode_segwit_address {
    my $hrp = $_[0];        #Human Readable Part (hrp).
    my $addr_to_decode = $_[1];
    my ($hrp_string, $data_ref) = decode_bech32($addr_to_decode);
    my @data_squashed_bits = @{$data_ref};
    die "Cannot decode Segwit address. The program (data) seems to be empty!" if (scalar @data_squashed_bits < 1);
    die "Cannot decode Segwit address. Witness versions above 16 are not specified!" if ($data_squashed_bits[0] > 16);
    #removes the first element of array.  In this case, the witness version.
    my $witness_version = shift @data_squashed_bits;
    #Convert from 5 sig bits to 8 sig bits.
    my $program_ref = convertbits(\@data_squashed_bits, 5, 8, 0);
    my @program = @{$program_ref};  # 'program' is the technical term for the data part of a segwit address.
    die "Cannot decode Segwit address. The program (data) is empty!" if (scalar @program == 0);
    die "Cannot decode Segwit address. The program (data) is too short!" if (scalar @program < 2);
    die "Cannot decode Segwit address. The program (data) is too long!" if (scalar @program > 40);
    #This check is recommended by BIP173.
    die "Cannot decode. Segwit addresses with witness version '0' must be either 20 or 32 bytes long!"
        if ($witness_version == 0 && scalar @program != 20 && scalar @program != 32);

    return ($witness_version, \@program);
}

# Data is an array with the preceeding char (witness version) removed.
# frombits and tobits are ints.
# pad is a boolean
# function convertbits (data, frombits, tobits, pad) 
sub convertbits {
    my $data_ref = $_[0];
    my $frombits = $_[1];  # The number of significant bits to convert from.
    my $tobits = $_[2];	   # The number of significant bits to convert to.
    my $pad_bool = $_[3];
    my $test;

    my @data_to_convert = @{$data_ref};
    # convertbits code converted from https://github.com/sipa/bech32/blob/master/ref/javascript/segwit_addr.js
    # I don't have a great understanding of how it works-- bitmagic.
    my $acc = 0;
    my $bits = 0;
    my @ret;
    my $maxv = (1 << $tobits) - 1;
    for (my $p = 0; $p < scalar @data_to_convert; ++$p) {
        my $value = hex($data_to_convert[$p]);
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
        die "Cannot convert bits! The bitmagic failed somehow.";
    }
    # Convert back to hex.
    foreach (@ret){ $_ = sprintf("%.2x", $_); }
    return \@ret;
}

# This sub takes a (presumably) bech32 encoded string and decodes it to a 5 bit 'squashed' byte array.
sub decode_bech32 {
    my $bech32_encoded_string = shift;
    my @bech32_encoded = split (//, $bech32_encoded_string, length($bech32_encoded_string));
    my $p; # p for pointer
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
    my $pos;  # pos is the index that corresponds to the final instance of '1', indicating the end of the human readable part.
    # We're trying to find the value of the $pos here.
    for ($pos = 0; $pos < scalar @bech32_encoded; $pos++){ 
        # Loops through until it finds a '1'
        if ( $bech32_encoded[$pos] eq  '1' ) { last; }
    }
    die "Cannot decode bech32: Human Readable Part is too short!" if ($pos < 1 );
    die "Cannot decode bech32: Data + checksum is too short!" if ($pos + 7 > scalar @bech32_encoded);
    die "Cannot decode bech32: Address is too long!" if (scalar @bech32_encoded >90);

    # Copy the human readable part to @hrp
    my @hrp;
    # This for loop will correctly place the data from @bech32_encoded into @hrp.
    for($p = 0; $p < $pos; $p++ ){
        $hrp[$p] = $bech32_encoded[$p];
    }
    my @decoded_hex_data;
    #For each of the chars in @bech32_encoded, find the hex value (index) of the bech32 char in CHARSET and save.
    for ($p = $pos + 1; $p < scalar @bech32_encoded; ++$p) {
        $d = -1;
        for (my $i = 0; $i < scalar @CHARSET; $i++) {
            if ($CHARSET[$i] eq $bech32_encoded[$p]){
                #d is the index of the char in CHARSET and also the corresponding value when converted to hex.
                $d = $i;
                last;
            }
        }
        die "Cannot decode bech32: Invalid bech32 character detected!" if ($d eq '-1');
        push @decoded_hex_data, $d;
    }
    my $hrp_str = join('', @hrp);
    my $vfyChk = verifyChecksum($hrp_str, \@decoded_hex_data); # Passes in the decoded hex representation of the bech32 char
    die "Cannot decode bech32: Invalid checksum!" if (!$vfyChk);
    my @data_to_ret;
    for ($p = 0; $p < scalar @decoded_hex_data - 6; $p++){
        $data_to_ret[$p] = $decoded_hex_data[$p];
    }
    #Convert the values in the return array to 2 digit hex values.
    foreach (@data_to_ret){ $_ = sprintf("%.2x", $_); }
    return ($hrp_str, \@data_to_ret);
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

# Consult https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp for how the polymod function works.
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

#Sample test taken from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses.
my $base58_encoded_address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
print "\nRunning tests for bitcoin address $base58_encoded_address\n";
print "Bitcoin address is valid.  Address type: '", check_bitcoin_address($base58_encoded_address), "'.\n";
my $binary_address = decodebase58tohex($base58_encoded_address);
print "Binary hexadecimal representation is: $binary_address\n";
my $reencoded_base58 = encodebase58fromhex($binary_address);
print "Re-encoded back to Base58 is: $reencoded_base58\n\n";
#Bech32 test.
my $bech32_encoded_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
print "Running test for bech32 address $bech32_encoded_address\n";
print "Valid ", check_bitcoin_address($bech32_encoded_address), ". For Bech32 encode/decode visit:https://slowli.github.io/bech32-buffer/\n\n";



