# dp.mp3 mapping: LibApplication.i opcode 0x114dc

Runtime call:

```text
LibApplication.i overload=121 sig=int i(int, java.lang.Object)
opcode=0x114dc (70876)
arg1=com.dexprotector.detector.envchecks.QrGen$Segment
ret=1584
```

Focused JNI resolver evidence:

```text
[JNI resolver] GetFieldID class="com.dexprotector.detector.envchecks.QrGen$Segment" name="bitLength" sig="I"
[JNI resolver] GetFieldID -> ... com.dexprotector.detector.envchecks.QrGen$Segment.bitLengthI
[LibApplication.i leave] ret=1584
```

Conclusion:

```java
// semantic equivalent
return ((QrGen.Segment) arg1).bitLength;
```

The member metadata is present in decrypted `dp_mp3_decompressed.bin`:

```text
QrGen$Segment descriptor/name strings are present
field name "bitLength" is present
```

The opcode itself was not found as a raw little-endian `dc140100` in the dump, so it is likely decoded/masked before dp-table lookup.
