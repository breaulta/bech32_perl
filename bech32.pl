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
  my $data_str = $_[1];
  my @hrp = split(//, $hrp_str, length($hrp_str));
  my @data = split(//, $data_str, length($data_str));
  #return polymod(hrpExpand(@hrp).concat(@data)) === 1;
  #my @returned_hrp = hrpExpand(@hrp);
    print "data after entering verifychksum: data:~$data_str~ hrp:~$hrp_str~\n";

    my $return;
    my $hrp_returned = hrpExpand($hrp_str);
    my @hrpExpanded = split(//, $hrp_returned, length($hrp_returned));
    push (@hrpExpanded, @data);
my $comb = $hrp_returned + $data_str;
print "\n TEST VERIFYCHECKSUM: ~$comb~\n";
    my $hrpE = join('', @hrpExpanded);
    print "my polystr inside verifyChecksum: ~$hrpE~";

    if ( polymod($hrpE) == 1){
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
#foreach 
#my $chksum_str = createChecksum($hrp_input_str, $hex_data_input_str);
my $chksum_ref = createChecksum($hrp_input_str, \@hex_data);
#my @chksum = split(//, $chksum_str, length($chksum_str));  #Must be hex array, because it is appended to the main data array
my @chksum = @{$chksum_ref};
foreach (@chksum) {print "\nchksum: ~$_~";}
  #$_ = hex($_) for @chksum;
#my $chksum_str = join('', @chksum);
#print "\nReturn from create checksum within encode: ~$chksum_str~\n";
  #my $combined = @data.concat(createChecksum(@hrp, @data));
  $_ = hex($_) for @hex_data;
  push @hex_data, @chksum;
 # $_ = hex($_) for @hex_data;
  push @hrp, 1; #should be bc1 (or tc1 for the testnet) now, and we're going to append the dereferenced char array
  for (my $p = 0; $p < scalar @hex_data; ++$p) {
    #@ret += $CHARSET.charAt($data[$p]);  push onto ret the char in CHARSET that matches 
    #push @ret, substr($CHARSET, $p-1, 1);
#looks like we're decoding indexes of CHARSET from @data into their respective chars for an encode
#print "\nhex_data: ~$hex_data[$p]~";
#print "\nreturned: ~$CHARSET[$hex_data[$p]]~";
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
  my $has_lower = 0;   #set to false
  my $has_upper = 0;   #set to false
  for ($p = 0; $p < scalar @bechArr; ++$p) {
    #if (@bechArr.charCodeAt($p) < 33 || @bechArr.charCodeAt($p) > 126) {
    if (ord($bechArr[$p]) < 33 || ord($bechArr[$p]) > 126) {
      return undef;
    }
    #if (@bechArr.charCodeAt($p) >= 97 && @bechArr.charCodeAt($p) <= 122) {
    if (ord($bechArr[$p]) >= 97 && ord($bechArr[$p]) <= 122) {
        $has_lower = 1;
    }
    if (ord($bechArr[$p]) >= 65 && ord($bechArr[$p]) <= 90) {
        $has_upper = 1;
    }
  }
  if ($has_lower && $has_upper) {
    return undef;
  }
  #@bechArr = @bechArr.toLowerCase();
  $_ = lc for @bechArr;
  #my $pos = @bechArr.lastIndexOf('1');
  my $pos;
  for ($pos = 0; $pos < scalar @bechArr; $pos++){
    if ( $bechArr[$pos] eq  '1' ) { last; }
  }
  #if ($pos < 1 || $pos + 7 > @bechArr.length || @bechArr.length > 90) {
  #my $var = $pos + 7;
  if ($pos < 1 || $pos + 7 > scalar @bechArr || scalar @bechArr > 90) {
    return undef;
  }

  #my @hrp = @bechArr.substring(0, $pos);
  my @hrp;
  for($p = 0; $p < $pos; $p++ ){
    $hrp[$p] = $bechArr[$p];
  }
  my @data;
  my $i;
  my $chset;
  my $bca;
  for ($p = $pos + 1; $p < scalar @bechArr; ++$p) {
    #my $d = $CHARSET.indexOf(@bechArr.charAt($p));
    #my $d = $CHARSET.indexOf($bechArr[$p]);
    $d = -1;
    for ($i = 0; $i < scalar @CHARSET; $i++) {
	#$chset = substr($CHARSET, $i-1, 1);
	#$chset = substr($CHARSET, $i-1, 1);
	#$bca = $bechArr[$p];
#print "Char from the CHARSET: $chset\n";
#print "Value from the becharray: $bca\n";
      #if (substr($CHARSET, $i-1, 1) eq $bechArr[$p]){
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
my $da = join('', @data);
print "data before verifychecksum: hrp:~$hrp_str~ data:~$da~\n";

my $vfyChk = verifyChecksum($hrp_str, $da);
print "verifyChecksum: $vfyChk\n";

  #if (!verifyChecksum(@hrp, @data)) {
  if (!$vfyChk) {
print "checksum bad\n";
    return undef;
  }
  my @data_ret;
  for ($p = 0; $p < scalar @data - 6; $p++){
    $data_ret[$p] = $data[$p];
  }
my $data_str = join('', @data_ret);
print "data: $data_str\n";

  #return {hrp: @hrp, data: @data.slice(0, @data.length - 6)};
  return ($hrp_str, $data_str);
}


#decode test
#print "\nStarting test for Decode...\n";
#my $test_decode_input = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
#my $expected_decode_output_data = "";
#my ($hrp_string, $data_string) = decode($test_decode_input);
#@out_data = @$data_ref;
#my $hrp_string = join('', @out_hrp);
#my $out_string = join('', @out_data);
#print "The input is: ~$test_decode_input~\n";
#print "The output is: hrp:~$hrp_string~ data:~$data_string~\n";

#encode test
print "\nStarting test for Encode...\n";
#print "Input: hrp:~$hrp_string~ data:~$out_string~\n";
my $expected_encoded_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
my $encode_hrp_input = "bc";
#Values used for this test are from: https://bitcointalk.org/index.php?topic=4992632.0
#The expected bech32 address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
#This data_to_encode is the witness version byte '0x00' + result of the ripemd-160 hash.  It needs a checksum to be complete
my $data_to_encode = "000e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16";
my $enc_out_str = encode($encode_hrp_input, $data_to_encode);
print "\n\nInput: hrp:~$encode_hrp_input~ data:~$data_to_encode~\n";
print "Output:           ~$enc_out_str~\n";
print "Output expected:  ~$expected_encoded_address~\n";


##the nonchar data array needs to keep the index integrity because there are more than 10 indexes (should be 32 right?)


