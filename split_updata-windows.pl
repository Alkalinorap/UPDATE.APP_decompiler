#!/usr/bin/perl
######################################################################
#
#   File          : split_updata.pl
#   Author(s)     : McSpoon
#   Description   : Unpack a Huawei U8220 'UPDATA.APP' file.
#                   http://pulse.modaco.com
#
#   Last Modified : Thu 24 December 2009
#   By            : McSpoon
#
#   Last Modified : Wed 18 June 2010
#   By            : ZeBadger (z e b a d g e r @ h o t m a i l . c o m)
#   Comment       : Added filename selection
#
#   Last Modified : Wed 19 June 2010
#   By            : ZeBadger (z e b a d g e r @ h o t m a i l . c o m)
#   Comment       : Added CRC checking
#
#   Last Modified : Sun 10 March 2013
#   By            : Fefifofum
#   Comment       : Adapted to U8815
#
######################################################################
 
use strict;
use warnings;
 
my %fileHash=(  "\x00\x00\x00\xFE","file18.mbn", #ASDP?
		"\x00\x00\x00\xFF","MD5_RSA", #file21.mbn
		"\x00\x00\x00\xE8","versions_boot.txt",
		"\x00\x00\x00\xD2","file10.mbn",
		"\x00\x00\x00\xF0","oemsblhd.mbn", #file09.mbn
		"\x00\x00\x00\xE2","qcsblhd_cfgdata.mbn",
		"\x00\x00\x00\xF1","file06.mbn",
		"\x00\x00\x00\xE0","qcsbl.mbn",
		"\x00\x00\x00\xE9","version_boot.txt",
		"\x00\x00\x00\xEE","modem_st1.mbn",
		"\x00\x00\x00\xEF","modem_st2.mbn",
		"\x00\x00\x00\xFB","appsboothd.mbn",
       		"\x00\x00\x00\x40","recovery.img",
		"\x00\x00\x00\xF9","file03.mbn",
		"\x00\x00\x00\x00","system.img.ext4",
		"\x00\x00\x00\xFA","file04.mbn",
		"\x00\x00\x00\x30","userdata.img.ext4",
		"\x00\x00\x00\xE4","oemlogo.mbn",
		"\x00\x00\x00\xED","misc.mbn", #file13.mbn
		"\x00\x00\x00\xF6","file01.mbn",
		"\x00\x00\x00\x70","cust.img.ext4",
		"\x00\x00\x00\xF3","file08.mbn",
		"\x00\x00\x00\xE3","oemsbl.mbn",
		"\x00\x00\x00\xF4","file02.mbn", #crc.mbn
		"\x00\x00\x00\xFC","boot.img",	
		"\x00\x00\x00\xEA","versions.txt",
		"\x00\x00\x00\x80","amssmbn.img",
		"\x00\x00\x00\xEC","version.txt",
		"\x00\x00\x00\xE6","all_versions.txt",
		"\x00\x00\x00\xE7","vendor.txt",
	);

my $unknown_count=0;

# Turn on print flushing.
$|++;
 
# Unsigned integers are 4 bytes.
use constant UINT_SIZE => 4;
 
# If a filename wasn't specified on the commmand line then
# assume the file to be unpacked is called "UPDATA.APP". 
my $FILENAME = undef;
if ($#ARGV == -1) {
	$FILENAME = "UPDATA.APP";
}
else {
	$FILENAME = $ARGV[0];
}
 
open(INFILE, $FILENAME) or die "Cannot open $FILENAME: $!\n";
binmode INFILE;
 
# Skip the first 92 bytes, they're blank.
#seek(INFILE, 92, 0);
 
# We'll dump the files into a folder called "output".
my $fileLoc=0;
my $BASEPATH = "output/";
mkdir $BASEPATH;

while (!eof(INFILE))
{
	$fileLoc=&find_next_file($fileLoc);
	seek(INFILE, $fileLoc, 0);
	$fileLoc=&dump_file();
}

close INFILE;
 

# Find the next file block in the main file
sub find_next_file
{
	my ($_fileLoc) = @_;
	my $_buffer = undef;
	my $_skipped=0;

	read(INFILE, $_buffer, UINT_SIZE);
	while ($_buffer ne "\x55\xAA\x5A\xA5" && !eof(INFILE))
	{
		read(INFILE, $_buffer, UINT_SIZE);
		$_skipped+=UINT_SIZE;
	}

	return($_fileLoc + $_skipped);
}
 
# Unpack a file block and output the payload to a file.
sub dump_file {
    my $buffer = undef;
    my $outfilename = undef;
    my $fileSeq;
    my $calculatedcrc = undef;
    my $sourcecrc = undef;
    my $fileChecksum;
 
    # Verify the identifier matches.
    read(INFILE, $buffer, UINT_SIZE); # Packet Identifier
    unless ($buffer eq "\x55\xAA\x5A\xA5") { die "Unrecognised file format. Wrong identifier.\n"; }
    read(INFILE, $buffer, UINT_SIZE); # Packet Length.
    my ($headerLength) = unpack("V", $buffer);
    read(INFILE, $buffer, 4);         # Always 1
    read(INFILE, $buffer, 8);         # Hardware ID
    read(INFILE, $fileSeq, 4);        # File Sequence
    if (exists($fileHash{$fileSeq})) {
	$outfilename=$fileHash{$fileSeq};
    } else {
	$outfilename="unknown_file.$unknown_count";
	$unknown_count++;
    }
    
    read(INFILE, $buffer, UINT_SIZE); # Data file length
    my ($dataLength) = unpack("V", $buffer);
    read(INFILE, $buffer, 16);        # File date
    read(INFILE, $buffer, 16);        # File time
    read(INFILE, $buffer, 16);        # The word INPUT ?
    read(INFILE, $buffer, 16);        # Blank
    read(INFILE, $buffer, 2);         # Checksum of the header maybe?
    read(INFILE, $buffer, 2);         # Always 1?
    read(INFILE, $buffer, 2);         # Blank

    # Grab the checksum of the file
    read(INFILE, $fileChecksum, $headerLength-98);
    $sourcecrc=slimhexdump($fileChecksum);
    
    # Dump the payload.
    read(INFILE, $buffer, $dataLength);
    open(OUTFILE, ">$BASEPATH$outfilename") or die "Unable to create $outfilename: $!\n";
    binmode OUTFILE;
    print OUTFILE $buffer;
    close OUTFILE;

    $calculatedcrc=`./crc $BASEPATH$outfilename`;
    chomp($calculatedcrc);

    print STDOUT "Extracted $outfilename";
    if ($calculatedcrc eq $sourcecrc)
	{
		print " - CRC Okay\n";
	}
	else
	{
		print " - ERROR: CRC did not match\n";
	}
    
    # Ensure we finish on a 4 byte boundary alignment.
    my $remainder = UINT_SIZE - (tell(INFILE) % UINT_SIZE);
    if ($remainder < UINT_SIZE) {
    	# We can ignore the remaining padding.
    	read(INFILE, $buffer, $remainder);
    }
    
    return (tell(INFILE));
}

sub hexdump ()
{
        my $num=0;
        my $i;
        my $rhs;
        my $lhs;
        my ($buf) = @_;
        my $ret_str="";

        foreach $i ($buf =~ m/./gs)
        {
                # This loop is to process each character at a time.
                #
                $lhs .= sprintf(" %02X",ord($i));

                if ($i =~ m/[ -~]/)
                {
                        $rhs .= $i;
                }
                else
                {
                        $rhs .= ".";
                }

                $num++;
                if (($num % 16) == 0)
                {
                        $ret_str.=sprintf("%-50s %s\n",$lhs,$rhs);
                        $lhs="";
                        $rhs="";
                }
        }
        if (($num % 16) != 0)
        {
                $ret_str.=sprintf("%-50s %s\n",$lhs,$rhs);
        }

	return ($ret_str);
}
        
sub slimhexdump ()
{
        my $i;
        my ($buf) = @_;
        my $ret_str="";

        foreach $i ($buf =~ m/./gs)
        {
                # This loop is to process each character at a time.
                #
                $ret_str .= sprintf("%02X",ord($i));
        }

	return ($ret_str);
}
        
