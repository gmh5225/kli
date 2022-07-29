# kli

Simple kernel-mode alternative to [lazy_importer](https://github.com/JustasMasiulis/lazy_importer).

# Example

```cpp
KLI_FN(KeBugCheck)(XBOX_360_SYSTEM_CRASH); // Same as KeBugCheck(XBOX_360_SYSTEM_CRASH);
KLI_FN(ExAllocatePoolWithTag)(NonPagedPool, PAGE_SIZE, 'enoN'); // Same as ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'enoN');
```

# How it works
The macro ``KLI_FN`` hashes the name of desired function in compiletime (using fnv1a64), and in runtime it will enumerate the Export Address Table (EAT) of ntoskrnl.exe to compare against this hash.
To get the kernel base, it uses the SIDT instruction to find the ``nt!KiDivideErrorFault`` Interrupt Service Routine (ISR), and abuses the fact that ntoskrnl.exe is mapped using 2MiB pages to walk downwards until
a valid PE image is found. To avoid issues with discardable sections, checks are ran on the PE image to make sure it's ntoskrnl (otherwise you risk finding random drivers).

# Output

```cpp
__int64 __fastcall sub_140001000(_BYTE *a1)
{
  __int64 v2; // [rsp+8h] [rbp-10h]

  v2 = 0xCBF29CE484222325ui64;
  while ( *a1 )
    v2 = 0x100000001B3i64 * ((char)*a1++ ^ (unsigned __int64)v2);
  return v2;
}

__int64 __fastcall sub_14000107C(__int64 a1)
{
  unsigned int i; // [rsp+20h] [rbp-58h]
  _DWORD *v3; // [rsp+28h] [rbp-50h]
  __int64 v4; // [rsp+40h] [rbp-38h]
  __int64 v5; // [rsp+58h] [rbp-20h]
  __int64 v6; // [rsp+60h] [rbp-18h]

  if ( !qword_140003000 )
    qword_140003000 = sub_1400011C4();
  v3 = (_DWORD *)(*(unsigned int *)(*(int *)(qword_140003000 + 60) + qword_140003000 + 136) + qword_140003000);
  v6 = (unsigned int)v3[7] + qword_140003000;
  v4 = (unsigned int)v3[8] + qword_140003000;
  v5 = (unsigned int)v3[9] + qword_140003000;
  for ( i = 0; i < v3[6]; ++i )
  {
    if ( sub_140001000((_BYTE *)(*(unsigned int *)(v4 + 4i64 * i) + qword_140003000)) == a1 )
      return *(unsigned int *)(v6 + 4i64 * *(unsigned __int16 *)(v5 + 2i64 * i)) + qword_140003000;
  }
  return 0i64;
}

__int64 sub_1400011C4()
{
  int j; // [rsp+20h] [rbp-38h]
  int v2; // [rsp+24h] [rbp-34h]
  __int64 v3; // [rsp+28h] [rbp-30h]
  __int64 i; // [rsp+30h] [rbp-28h]

  for ( i = *(_QWORD *)((char *)KeGetPcr()->IdtBase + 4) >> 12 << 12; i; i -= 4096i64 )
  {
    for ( j = 0; j < 4089; ++j )
    {
      v3 = j + i;
      if ( *(_BYTE *)v3 == 72
        && *(unsigned __int8 *)(v3 + 1) == 141
        && *(_BYTE *)(v3 + 2) == 61
        && *(unsigned __int8 *)(v3 + 6) == 255
        && *(_BYTE *)(v3 + 7) == 72
        && *(_BYTE *)(v3 + 8) == 99
        || *(_BYTE *)v3 == 72
        && *(unsigned __int8 *)(v3 + 1) == 141
        && *(_BYTE *)(v3 + 2) == 61
        && *(unsigned __int8 *)(v3 + 6) == 255
        && *(_BYTE *)(v3 + 7) == 72
        && *(unsigned __int8 *)(v3 + 8) == 139
        && *(unsigned __int8 *)(v3 + 9) == 140
        && *(unsigned __int8 *)(v3 + 15) == 232
        || *(_BYTE *)v3 == 76
        && *(unsigned __int8 *)(v3 + 1) == 141
        && *(_BYTE *)(v3 + 2) == 61
        && *(unsigned __int8 *)(v3 + 6) == 255
        && *(_BYTE *)(v3 + 7) == 72
        && *(unsigned __int8 *)(v3 + 8) == 152 )
      {
        v2 = *(_DWORD *)(v3 + 3);
        if ( (((_WORD)v3 + (_WORD)v2 + 7) & 0xFFF) == 0 )
          return v3 + v2 + 7;
      }
    }
  }
  return 0i64;
}

NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  void (__fastcall *v3)(__int64); // [rsp+20h] [rbp-18h]
  void (__fastcall *v4)(_QWORD, __int64, __int64); // [rsp+28h] [rbp-10h]

  v3 = (void (__fastcall *)(__int64))sub_14000107C(0xDA68D5AF5F40988Fui64);
  v3(864i64);
  v4 = (void (__fastcall *)(_QWORD, __int64, __int64))sub_14000107C(0xB456343AD290F91Fui64);
  v4(0i64, 4096i64, 1701736270i64);
  return 0;
}
```

# Credits
- https://twitter.com/JustasMasiulis for making [lazy_importer](https://github.com/JustasMasiulis/lazy_importer)
- https://twitter.com/Ch40zz_ codereview/debugging
- https://twitter.com/duk_37 codereview
- https://github.com/Ahora57 for [GetKernelBaseEx](https://github.com/Ahora57/GetKernelBaseEx)
