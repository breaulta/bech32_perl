#!/usr/bin/perl
use warnings;
#use strict;

my $CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
my @GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

sub polymod {
  my $valRef = $_[0];
  my @values = @{$valRef};
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

sub hrpExpand {
  my $hrpRef = $_[0];;
  my @hrp = @{$hrpRef};
  my @ret;
  my $p;

my $hrp_ = join('', @hrp);
print "my hrp inside hrpExpand: ~$hrp_~";

  for ($p = 0; $p < scalar @hrp; ++$p) {
print "pass 1\n";
    #@ret.push(@hrp.charCodeAt($p) >> 5);
    push @ret, ord($hrp[$p]) >> 5;
  }
  push @ret, 0;
  for ($p = 0; $p < scalar @hrp; ++$p) {
print "pass 2\n";
    #@ret.push(@hrp.charCodeAt($p) & 31);
    push @ret, ord($hrp[$p]) & 31;
  }
my $ret_len = scalar @ret;
my $ret_str = join('', @ret);
print "\nReturn from hrpExpand: ~$ret_str~ size:$ret_len\n";

  return \@ret;
}

sub verifyChecksum {
  my ($hrp_ref, $data_ref) = @_;
  my @hrp = @{$hrp_ref};
  my @data = @{$data_ref};
  #return polymod(hrpExpand(@hrp).concat(@data)) === 1;
  #my @returned_hrp = hrpExpand(@hrp);
my $hr = join('', @hrp);
my $da = join('', @data);
print "data after entering verifychksum: data:~$da~ hrp:$hr\n";

my $return;
my $hrp_returned_ref = hrpExpand(\@hrp);
my @hrpExpanded = @{$hrp_returned_ref};
my @polyArr = push @hrpExpanded, @data;

my $polystr = join('', @polyArr);
print "my polystr inside verifyChecksum: ~$polystr~";

if ( polymod(\@polyArr) == 1){
    $return = 1;
}else{
    $return = 0;
}
  #return polymod(push hrpExpand(@hrp), @data) == 1;
  #return polymod(push hrpExpand(@hrp), @data) == 1;
  return $return;
}

sub createChecksum {
  my ($hrp_ref, $data_ref) = @_;
  my @hrp = @{$hrp_ref};
  my @data = @{$data_ref};

my $data_str = join('', @data);
print "\n\@data inside createChecksum: ~$data_str~\n";


my @expanded = @{hrpExpand(\@hrp)};
my $exp_str = join('', @expanded);
print "\n\@expanded: ~$exp_str~\n";
  #my @values = hrpExpand(@hrp).concat(@data).concat([0, 0, 0, 0, 0, 0]);
  my @values = push @expanded, (push @data, (0, 0, 0, 0, 0, 0));
my $val_str = join('', @values);
print "\n\@values: ~$val_str~\n";
  my $mod = polymod(\@values) ^ 1;
  my @ret;
  for (my $p = 0; $p < 6; ++$p) {
    #@ret.push((mod >> 5 * (5 - $p)) & 31);
    push @ret, (($mod >> 5 * (5 - $p)) & 31);
  }
  return \@ret;
}

sub encode {
  my ($hrp_ref, $data_ref) = @_;
  my @hrp = @{$hrp_ref};
  my @data = @{$data_ref};

my @chksum = @{createChecksum(\@hrp, \@data)};
my $chksum_str = join('', @chksum);
print "\nReturn from create checksum within encode: ~$chksum_str~\n";
  #my $combined = @data.concat(createChecksum(@hrp, @data));
  my @combined = push @data, @chksum;
  my @ret = push @hrp, 1;
  for (my $p = 0; $p < scalar @combined; ++$p) {
    #@ret += $CHARSET.charAt(combined[$p]);
    push @ret, substr($CHARSET, $p-1, 1);
  }
  return \@ret;
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
    for ($i = 0; $i < length($CHARSET); $i++) {
	$chset = substr($CHARSET, $i-1, 1);
	$bca = $bechArr[$p];
#print "Char from the CHARSET: $chset\n";
#print "Value from the becharray: $bca\n";
      if (substr($CHARSET, $i-1, 1) eq $bechArr[$p]){
	$d = $bechArr[$p];
	last;
      }
    }
    if ($d eq '-1') {
#print "d is -1\n";
      return undef;
    }
    push @data, $d;
  }

my $da = join('', @data);
print "data before verifychecksum: ~$da~\n";

my $vfyChk = verifyChecksum(\@hrp, \@data);
print "verifyChecksum: $vfyChk\n";

  #if (!verifyChecksum(@hrp, @data)) {
  if (!$vfyChk) {
#print "checksum bad\n";
    return undef;
  }
  my @data_ret;
  for ($p = 0; $p < scalar @data - 6; $p++){
    $data_ret[$p] = $data[$p];
  }
my $data_str = join('', @data);
print "data: $data_str\n";

  #return {hrp: @hrp, data: @data.slice(0, @data.length - 6)};
  return (\@hrp, \@data);
}


#decode test
print "\nStarting test for Decode...\n";
my $test_decode_input = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx";
my $expected_data = "pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx";
#my $expected_data = "010e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e160e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16";
#my $expected_data = "thisis a test";
#my $test_decode_input = "";
#my $expected_decode_output_data = "";
my ($hrp_ref, $data_ref) = decode($test_decode_input);
my @out_hrp = @{$hrp_ref};
my @out_data = @{$data_ref};
#@out_data = @$data_ref;
my $hrp_string = join('', @out_hrp);
my $out_string = join('', @out_data);
print "The input is: ~$test_decode_input~\n";
print "The output is: hrp:~$hrp_string~ data:~$out_string~\n";

#encode test
print "\nStarting test for Encode...\n";
#print "Input: hrp:~$hrp_string~ data:~$out_string~\n";
print "Input: hrp:~$hrp_string~ data:~$expected_data~\n";
my @exp_data = split (//, $expected_data, length($expected_data));
my $encode_ref = encode(\@out_hrp, \@exp_data );
my @encode_out = @{$encode_ref};
my $enc_out_str = join('', @encode_out);
print "Output: ~$enc_out_str~\n";






