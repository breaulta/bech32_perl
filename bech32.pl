#!/usr/bin/perl
use warnings;
use strict;

my @CHARSET = ('q','p','z','r','y','9','x','8','g','f','2','t','v','d','w','0','s','3','j','n','5','4','k','h','c','e','6','m','u','a','7','l');
my @GENERATOR = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3);

sub polymod {
  my $val_ref = $_[0];
  my @values = @{$val_ref};
#foreach(@values){ print "vals in polymod: ~$_~\n"; }
  my $chk = 1;
  for (my $p = 0; $p < scalar @values; ++$p) {
    my $top = $chk >> 25;
    $chk = ($chk & 0x1ffffff) << 5 ^ $values[$p];
#print "values of p:~$p~ vals:~$values[$p]~ chk:~$chk~ top:~$top~\n";
    for (my $i = 0; $i < 5; ++$i) {
      if (($top >> $i) & 1) {
        $chk ^= $GENERATOR[$i];
#print "values of Generator: i:~$i~ Gen: ~$GENERATOR[$i]~ Chk:~$chk~\n";
      }
    }
  }
  return $chk;
}

sub hrpExpand {
  my $hrp_str = $_[0];
  my @hrp = split(//, $hrp_str, length($hrp_str));
  my @ret;
  my $p;
  for ($p = 0; $p < scalar @hrp; ++$p) {
    push @ret, ord($hrp[$p]) >> 5;
  }
  push @ret, 0;
  for ($p = 0; $p < scalar @hrp; ++$p) {
    push @ret, ord($hrp[$p]) & 31;
  }
#foreach(@ret) { print "\nhrpExpand: ~$_~";}
  return \@ret;
}

sub verifyChecksum {
  my $hrp_str = $_[0];
  my $data_ref = $_[1];
  my @data = @{$data_ref};
  my $return;
  my $exp_ref = hrpExpand($hrp_str);
  my @hrp_exp = @{$exp_ref};
  push @hrp_exp, @data;
  my $poly = polymod(\@hrp_exp);

    if ( $poly  == 1){
	$return = 1;
    }else{
	$return = 0;
    }
  return $return;
}

sub createChecksum {   #Returns Array of ?
  my $hrp_str = $_[0];
  my $data_ref = $_[1];
  my @data = @{$data_ref};
#foreach (@data) { print "Data passed to createChecksum: ~$_~\n";}
my $exp_ref = hrpExpand($hrp_str);  #Returns Array of hex decimals from the hrp
my @hrp_exp = @{$exp_ref};
#foreach (@hrp_exp) { print "hrp_exp: ~$_~\n";}
  #push @hrp_exp, (push @data, (0, 0, 0, 0, 0, 0));
$_ = hex($_) for @data;
  push @data, (0, 0, 0, 0, 0, 0);
  push @hrp_exp, @data;
  my $mod = polymod(\@hrp_exp) ^ 1;
  my @ret;
  for (my $p = 0; $p < 6; ++$p) {
    
    push @ret, (($mod >> 5 * (5 - $p)) & 31);
  }
  return \@ret;
}

sub encode {
  my $hrp_input_str = $_[0];
  my $hex_data_input_str = $_[1];  #the data here corresponds to numbers that reference the indexes of the CHARSET
  my @hrp = split(//, $hrp_input_str, length($hrp_input_str));
  #my @hex_data = split(//, $hex_data_input_str, length($hex_data_input_str));

  die "Cannot Encode! There Must Be an Even Number of Hex Data Input Chars!" unless length($hex_data_input_str) % 2 == 0;
  die "Cannot Encode! Invalid Hexadecimal Character(s)!\n" unless $hex_data_input_str =~ /^[a-f0-9]*$/i;
  #convert input string into byte array
  my @hex_data = $hex_data_input_str =~ /../g;
  #convert to lower case to satisfy perl's disdain for uppercase
my $chksum_ref = createChecksum($hrp_input_str, \@hex_data);
my @chksum = @{$chksum_ref};
my @print_chksum = @{$chksum_ref};
print "\nComputed Checksum: ";
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

sub decode {
  my $bechString = $_[0];
  #convert string to array
  my @bechArr = split (//, $bechString, length($bechString));
  my $p;
  my $d;
  my $has_lowercase = 0;   #set to false
  my $has_uppercase = 0;   #set to false
  for ($p = 0; $p < scalar @bechArr; ++$p) {
    #Check if the chars are 'normal' punctuation, numbers, letters
    if (ord($bechArr[$p]) < 33 || ord($bechArr[$p]) > 126) {
      return undef;
    }
    if (ord($bechArr[$p]) >= 97 && ord($bechArr[$p]) <= 122) {
        $has_lowercase = 1;
    }
    if (ord($bechArr[$p]) >= 65 && ord($bechArr[$p]) <= 90) {
        $has_uppercase = 1;
    }
  }
  if ($has_lowercase && $has_uppercase) {
    return undef;
  }
  #Convert @bechArr to lowercase
  $_ = lc for @bechArr;
  #my $pos = @bechArr.lastIndexOf('1');
  my $pos;
  for ($pos = 0; $pos < scalar @bechArr; $pos++){
    if ( $bechArr[$pos] eq  '1' ) { last; }
  }
  #my $var = $pos + 7;
  #check if the human readable part and full string aren't too long
  if ($pos < 1 || $pos + 7 > scalar @bechArr || scalar @bechArr > 90) {
    return undef;
  }
  #my @hrp = @bechArr.substring(0, $pos);
  #Copy the human readable part to @hrp
  my @hrp;
  for($p = 0; $p < $pos; $p++ ){
    $hrp[$p] = $bechArr[$p];
  }
  my @data;
  my $i;
  my $chset;
  my $bca;
  for ($p = $pos + 1; $p < scalar @bechArr; ++$p) {
    $d = -1;
    for ($i = 0; $i < scalar @CHARSET; $i++) {
      if ($CHARSET[$i] eq $bechArr[$p]){
	#$d = $bechArr[$p];
	#d is the index of the char in CHARSET
	$d = $i;
	last;
      }
    }
    if ($d eq '-1') {
#print "d is -1\n";
      return undef;
    }
    push @data, $d;
  }

  my $hrp_str = join('', @hrp);
  my $vfyChk = verifyChecksum($hrp_str, \@data);
  if (!$vfyChk) {
    return undef;
  }
  my @data_ret;
  for ($p = 0; $p < scalar @data - 6; $p++){
    $data_ret[$p] = $data[$p];
  }
  #Convert the return array to a 2 digit hex number.
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

  my @data = @{$data_ref};
  my $acc = 0;
  my $bits = 0;
  my @ret;
  my $maxv = (1 << $tobits) - 1;
  for (my $p = 0; $p < @data.length; ++$p) {
    var value = @data[p];
    if (value < 0 || (value >> frombits) !== 0) {
      return null;
    }
    $acc = ($acc << frombits) | value;
    $bits += frombits;
    while ($bits >= $tobits) {
      $bits -= $tobits;
      ret.push(($acc >> $bits) & maxv);
    }
  }
  if (pad) {
    if ($bits > 0) {
      ret.push(($acc << ($tobits - $bits)) & maxv);
    }
  } else if ($bits >= frombits || (($acc << ($tobits - $bits)) & maxv)) {
    return null;
  }
  return ret;
}

function decode (hrp, addr) {
  var dec = bech32.decode(addr);
  if (dec === null || dec.hrp !== hrp || dec.@data.length < 1 || dec.@data[0] > 16) {
    return null;
  }
  var res = convertbits(dec.@data.slice(1), 5, 8, false);
  if (res === null || res.length < 2 || res.length > 40) {
    return null;
  }
  if (dec.@data[0] === 0 && res.length !== 20 && res.length !== 32) {
    return null;
  }
  return {version: dec.@data[0], program: res};
}

function encode (hrp, version, program) {
  var ret = bech32.encode(hrp, [version].concat(convertbits(program, 8, 5, true)));
  if (decode(hrp, ret) === null) {
    return null;
  }
  return ret;
}

##the nonchar data array needs to keep the index integrity because there are more than 10 indexes (should be 32 right?)

#my $bech32_encoded_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
#my $bech32_encoded_address = "A12UEL5L";
#my $bech32_encoded_address = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs";
my $bech32_encoded_address = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
#my $bech32_encoded_address = "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j";
#my $bech32_encoded_address = "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w";
#my $bech32_encoded_address = "?1ezyfcl";
print "\nRunning tests for bech32 address $bech32_encoded_address\n";
my ($hrp_string, $data_ref) = decode($bech32_encoded_address);
my @out_data = @{$data_ref};
print "\nThe bech32 decode output:\nhuman readable part(hrp): $hrp_string\nData in base 32 hex: ";
foreach (@out_data){ print "$_"; }
my $data_to_encode = join('', @out_data);
my $reencoded_bech32 = encode($hrp_string, $data_to_encode);
print "\nRe-encoded back to bech32 is: $reencoded_bech32";
print "\nOriginal bech32 address     : $bech32_encoded_address\n\n";



