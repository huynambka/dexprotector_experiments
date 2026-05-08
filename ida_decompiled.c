

/********************************************************************************/
Function: sub_378
/********************************************************************************/

int sub_378()
{
  __int64 (__fastcall *v0)(_QWORD, _QWORD); // x0
  unsigned __int64 v1; // x11
  __int64 v2; // x12
  bool v3; // w13
  int **v4; // x10
  int v5; // w8

  LODWORD(v0) = linux_eabi_syscall(__NR_prctl, 4, nullptr, nullptr);
  v1 = 0;
  v2 = 0;
  v3 = 1;
  v4 = off_50;
  while ( *((_DWORD *)v4 - 4) != 1 || ++v2 != 4 )
  {
    ++v1;
    v4 += 7;
    v3 = v1 < 8;
    if ( v1 == 8 )
      goto LABEL_10;
  }
  if ( !v3 )
  {
LABEL_10:
    dword_B228 = 404;
    return (int)v0;
  }
  v0 = (__int64 (__fastcall *)(_QWORD, _QWORD))sub_2434((char *)&dword_0 + (_QWORD)*v4, v4[2]);
  if ( v0 )
    v5 = 0;
  else
    v5 = 500;
  off_B230 = v0;
  dword_B228 = v5;
  return (int)v0;
}



/********************************************************************************/
Function: JNI_OnLoad
/********************************************************************************/

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  int v3; // w0

  if ( dword_B228 )
    return -dword_B228;
  v3 = off_B230(vm, 0);
  off_B230 = nullptr;
  if ( v3 )
    return -v3;
  else
    return 65540;
}



/********************************************************************************/
Function: sub_488
/********************************************************************************/

unsigned __int64 __fastcall sub_488(unsigned __int64 result, unsigned __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // x8
  unsigned __int64 v4; // x9
  unsigned __int64 v5; // x10
  _BYTE *v6; // x8
  char *v7; // x9
  char v8; // t1
  unsigned __int64 v9; // x11
  _BYTE *v10; // x9
  char *v11; // x10
  unsigned __int64 v12; // x8
  unsigned __int64 v13; // x11
  __int128 *v14; // x8
  _OWORD *v15; // x9
  unsigned __int64 v16; // x10
  __int128 v17; // q0
  __int128 v18; // q1
  __int64 *v19; // x13
  _QWORD *v20; // x14
  unsigned __int64 v21; // x11
  __int64 v22; // t1
  __int128 *v23; // x10
  _OWORD *v24; // x12
  unsigned __int64 v25; // x13
  __int128 v26; // q0
  __int128 v27; // q1
  unsigned __int64 v28; // x13
  unsigned __int64 v29; // x14
  unsigned __int64 v30; // x11
  __int64 v31; // d0
  char v32; // t1

  if ( a2 >= result )
  {
    if ( !a3 )
      return result;
    if ( a3 < 8 || result - a2 < 0x20 )
    {
      v10 = (_BYTE *)result;
      v11 = (char *)a2;
      v12 = a3;
      goto LABEL_34;
    }
    if ( a3 >= 0x20 )
    {
      v9 = a3 & 0xFFFFFFFFFFFFFFE0LL;
      v14 = (__int128 *)(a2 + 16);
      v15 = (_OWORD *)(result + 16);
      v16 = a3 & 0xFFFFFFFFFFFFFFE0LL;
      do
      {
        v17 = *(v14 - 1);
        v18 = *v14;
        v14 += 2;
        v16 -= 32LL;
        *(v15 - 1) = v17;
        *v15 = v18;
        v15 += 2;
      }
      while ( v16 );
      if ( v9 == a3 )
        return result;
      if ( (a3 & 0x18) == 0 )
      {
        v12 = a3 & 0x1F;
        v11 = (char *)(a2 + v9);
        v10 = (_BYTE *)(result + v9);
        goto LABEL_34;
      }
    }
    else
    {
      v9 = 0;
    }
    v12 = a3 & 7;
    v10 = (_BYTE *)(result + (a3 & 0xFFFFFFFFFFFFFFF8LL));
    v11 = (char *)(a2 + (a3 & 0xFFFFFFFFFFFFFFF8LL));
    v19 = (__int64 *)(a2 + v9);
    v20 = (_QWORD *)(result + v9);
    v21 = v9 - (a3 & 0xFFFFFFFFFFFFFFF8LL);
    do
    {
      v22 = *v19++;
      v21 += 8LL;
      *v20++ = v22;
    }
    while ( v21 );
    if ( (a3 & 0xFFFFFFFFFFFFFFF8LL) == a3 )
      return result;
    do
    {
LABEL_34:
      v32 = *v11++;
      --v12;
      *v10++ = v32;
    }
    while ( v12 );
    return result;
  }
  if ( !a3 )
    return result;
  v3 = result + a3;
  v4 = a2 + a3;
  if ( a3 < 8 || v4 - v3 < 0x20 )
  {
    v5 = a3;
    goto LABEL_6;
  }
  if ( a3 >= 0x20 )
  {
    v13 = a3 & 0xFFFFFFFFFFFFFFE0LL;
    v23 = (__int128 *)(a2 + a3 - 16);
    v24 = (_OWORD *)(result + a3 - 16);
    v25 = a3 & 0xFFFFFFFFFFFFFFE0LL;
    do
    {
      v27 = *(v23 - 1);
      v26 = *v23;
      v25 -= 32LL;
      v23 -= 2;
      *(v24 - 1) = v27;
      *v24 = v26;
      v24 -= 2;
    }
    while ( v25 );
    if ( v13 == a3 )
      return result;
    if ( (a3 & 0x18) == 0 )
    {
      v5 = a3 & 0x1F;
      v4 -= v13;
      v3 -= v13;
LABEL_6:
      v6 = (_BYTE *)(v3 - 1);
      v7 = (char *)(v4 - 1);
      do
      {
        v8 = *v7--;
        --v5;
        *v6-- = v8;
      }
      while ( v5 );
      return result;
    }
  }
  else
  {
    v13 = 0;
  }
  v5 = a3 & 7;
  v3 -= a3 & 0xFFFFFFFFFFFFFFF8LL;
  v4 -= a3 & 0xFFFFFFFFFFFFFFF8LL;
  v28 = a2 + -8LL - v13;
  v29 = result + -8LL - v13;
  v30 = v13 - (a3 & 0xFFFFFFFFFFFFFFF8LL);
  do
  {
    v31 = *(_QWORD *)(v28 + a3);
    v28 -= 8LL;
    v30 += 8LL;
    *(_QWORD *)(v29 + a3) = v31;
    v29 -= 8LL;
  }
  while ( v30 );
  if ( (a3 & 0xFFFFFFFFFFFFFFF8LL) != a3 )
    goto LABEL_6;
  return result;
}



/********************************************************************************/
Function: sub_63C
/********************************************************************************/

unsigned __int64 __fastcall sub_63C(unsigned __int64 result, unsigned __int8 a2, unsigned __int64 a3)
{
  unsigned __int8 *v3; // x8
  int32x4_t *v4; // x11
  unsigned __int64 v5; // x12
  unsigned int v6; // w9
  unsigned __int64 v7; // x12
  unsigned __int64 v8; // x10
  int32x4_t *v9; // x8
  __int64 v10; // x14
  int32x4_t v11; // q0
  int32x4_t *v12; // x11
  unsigned __int64 v13; // x9

  if ( a3 <= 0xB )
  {
    if ( a3 )
    {
      v3 = (unsigned __int8 *)result;
      do
      {
        --a3;
        *v3++ = a2;
      }
      while ( a3 );
    }
    return result;
  }
  v4 = (int32x4_t *)result;
  v5 = result & 3;
  if ( (result & 3) != 0 )
  {
    *(_BYTE *)result = a2;
    v4 = (int32x4_t *)(result + 1);
    if ( v5 != 3 )
    {
      *(_BYTE *)(result + 1) = a2;
      if ( v5 == 2 )
      {
        v4 = (int32x4_t *)(result + 2);
      }
      else
      {
        v4 = (int32x4_t *)(result + 3);
        *(_BYTE *)(result + 2) = a2;
      }
    }
    a3 += result | 0xFFFFFFFFFFFFFFFCLL;
  }
  v6 = 16843009 * a2;
  v7 = a3 >> 2;
  if ( a3 < 0x20 )
  {
    v8 = a3 >> 2;
    v9 = v4;
    do
    {
LABEL_17:
      --v8;
      v9->n128_u32[0] = v6;
      v9 = (int32x4_t *)((char *)v9 + 4);
    }
    while ( v8 );
    goto LABEL_18;
  }
  v8 = (a3 >> 2) & 7;
  v10 = v7 & 0x3FFFFFFFFFFFFFF8LL;
  v11 = vdupq_n_s32(v6);
  v9 = (int32x4_t *)((char *)v4 + 4 * (v7 & 0x3FFFFFFFFFFFFFF8LL));
  v12 = v4 + 1;
  do
  {
    v12[-1] = v11;
    *v12 = v11;
    v12 += 2;
    v10 -= 8;
  }
  while ( v10 );
  if ( v7 != (v7 & 0x3FFFFFFFFFFFFFF8LL) )
    goto LABEL_17;
LABEL_18:
  v13 = a3 & 3;
  if ( (a3 & 3) != 0 )
  {
    v9->n128_u8[0] = a2;
    if ( v13 != 1 )
    {
      v9->n128_u8[1] = a2;
      if ( v13 != 2 )
        v9->n128_u8[2] = a2;
    }
  }
  return result;
}



/********************************************************************************/
Function: sub_720
/********************************************************************************/

__int64 __fastcall sub_720(unsigned __int8 *a1, unsigned __int8 *a2)
{
  int v2; // w9
  unsigned int v3; // w8

  while ( 1 )
  {
    v2 = *a1;
    v3 = v2 - *a2;
    if ( v3 )
      break;
    ++a2;
    ++a1;
    if ( !v2 )
      return 0;
  }
  return v3;
}



/********************************************************************************/
Function: sub_748
/********************************************************************************/

unsigned __int8 *__fastcall sub_748(unsigned __int8 *a1, unsigned __int8 a2)
{
  unsigned __int8 *result; // x0
  unsigned __int8 *v4; // x10
  int v5; // w11
  int v6; // t1

  result = nullptr;
  v4 = a1;
  do
  {
    v6 = *v4++;
    v5 = v6;
    if ( v6 == a2 )
      result = a1;
    a1 = v4;
  }
  while ( v5 );
  return result;
}



/********************************************************************************/
Function: sub_770
/********************************************************************************/

unsigned __int64 __fastcall sub_770(unsigned __int8 *a1, _QWORD *a2, unsigned int a3)
{
  unsigned __int8 *v3; // x10
  int v4; // w8
  int v5; // t1
  unsigned int v6; // w9
  int v8; // w9
  int v9; // t1
  unsigned __int64 v10; // x8
  int v12; // w11
  __int64 v13; // x12
  unsigned __int64 v14; // x11
  int v15; // w14
  unsigned __int64 v16; // x13
  unsigned __int8 *v17; // x10
  int v18; // w15
  int v19; // t1
  int v20; // w2
  int v21; // w2
  int v22; // t1
  int v23; // t1

  if ( a3 <= 0x24 && a3 != 1 )
  {
    v3 = a1;
    do
    {
      v5 = *v3++;
      v4 = v5;
      v6 = v5 - 14;
    }
    while ( v5 == 32 || v6 > 0xFFFFFFFA );
    if ( v4 == 43 || v4 == 45 )
    {
      v9 = *v3++;
      v8 = v9;
      if ( (a3 & 0xFFFFFFEF) != 0 )
        goto LABEL_21;
    }
    else
    {
      v8 = v4;
      if ( (a3 & 0xFFFFFFEF) != 0 )
        goto LABEL_21;
    }
    if ( v8 == 48 )
    {
      if ( (*v3 | 0x20) == 0x78
        && ((v8 = v3[1], (unsigned int)(v8 - 58) > 0xFFFFFFF5) || (v3[1] & 0xDFu) - 71 >= 0xFFFFFFFA) )
      {
        v3 += 2;
        a3 = 16;
      }
      else
      {
        v8 = 48;
        if ( !a3 )
          a3 = 8;
      }
      goto LABEL_27;
    }
LABEL_21:
    if ( v8 == 48 )
      v12 = 8;
    else
      v12 = 10;
    if ( !a3 )
      a3 = v12;
LABEL_27:
    v13 = a3;
    v14 = 0;
    v15 = 0;
    v16 = 0xFFFFFFFFFFFFFFFFLL / a3;
    v17 = v3 - 1;
    v18 = ~(v16 * a3);
    while ( 1 )
    {
      v20 = v8 - 48;
      if ( (unsigned int)(v8 - 48) >= 0xA )
      {
        if ( (v8 & 0xFFFFFFDF) - 91 < 0xFFFFFFE6 )
          break;
        if ( (unsigned int)(v8 - 91) >= 0xFFFFFFE6 )
          v21 = -55;
        else
          v21 = -87;
        v20 = v21 + v8;
      }
      if ( v20 >= (int)v13 )
        break;
      if ( v15 < 0 )
      {
        v19 = *++v17;
        v8 = v19;
        v15 = -1;
      }
      else if ( v14 > v16 || v14 == v16 && v20 > v18 )
      {
        v22 = *++v17;
        v8 = v22;
        v15 = -1;
        v14 = -1;
      }
      else
      {
        v15 = 1;
        v14 = v14 * v13 + v20;
        v23 = *++v17;
        v8 = v23;
      }
    }
    if ( v15 > 0 && v4 == 45 )
      v10 = -(__int64)v14;
    else
      v10 = v14;
    if ( a2 )
    {
      if ( v15 )
        a1 = v17;
      goto LABEL_51;
    }
    return v10;
  }
  v10 = 0;
  if ( !a2 )
    return v10;
LABEL_51:
  *a2 = a1;
  return v10;
}



/********************************************************************************/
Function: sub_918
/********************************************************************************/

__int64 __fastcall sub_918(__int64 result, __int64 a2)
{
  int v2; // w5
  int v3; // w8
  int v4; // w9
  int v5; // w19
  int v6; // w21
  unsigned int v7; // w3
  int v8; // w4
  unsigned int v9; // w6
  int v10; // w7
  int v11; // w22
  unsigned __int64 v12; // t2
  __int64 v13; // x5
  int v14; // w22
  unsigned int v15; // w21
  bool v16; // zf
  int v17; // w23
  __int16 v18; // w20
  int v19; // w19
  __int16 v20; // w21
  unsigned int v21; // w6
  __int128 *v22; // x4
  __int128 v23; // q1
  unsigned __int8 *v24; // x8
  int v25; // w9
  unsigned int v26; // w10
  __int128 v27; // [xsp+0h] [xbp-BC0h] BYREF
  __int128 v28; // [xsp+10h] [xbp-BB0h]
  _OWORD v29[4]; // [xsp+B00h] [xbp-C0h] BYREF
  _OWORD v30[4]; // [xsp+B40h] [xbp-80h] BYREF

  v2 = 0;
  v3 = 0;
  v4 = 0;
  v5 = 11008;
  v27 = xmmword_A7B8;
  v28 = xmmword_A7C8;
  memset(v30, 0, sizeof(v30));
  memset(v29, 0, sizeof(v29));
  while ( 2 )
  {
    v6 = *(__int16 *)((char *)&word_A7DA[-5504] + (v5 & 0xFFFFFFFE));
    v7 = *((unsigned __int16 *)v30 + (((_BYTE)v4 + 30) & 0x1F));
    v8 = v2;
    v9 = *(unsigned __int16 *)((char *)&word_A7DA[-5504] + (v5 & 0xFFFFFFFE));
    if ( v6 < 0 )
    {
      v10 = 0;
      v2 = v9 & 0x7FFF;
      v11 = -1;
    }
    else
    {
      v10 = 0;
      v11 = 256;
      switch ( v9 >> 13 )
      {
        case 0u:
        case 2u:
          v10 = 0;
          v11 = 0;
          break;
        case 1u:
          break;
        case 3u:
          v11 = v9 & 0xF00;
          v10 = 1;
          break;
        default:
          v10 = 0;
          v11 = -1;
          break;
      }
    }
    HIDWORD(v12) = v11;
    LODWORD(v12) = v11;
    switch ( (unsigned int)(v12 >> 8) )
    {
      case 0u:
        v2 = v8;
        if ( (v9 & 0x8000) == 0 )
          goto LABEL_52;
        goto LABEL_55;
      case 1u:
        v2 = *((unsigned __int16 *)v30 + (((_BYTE)v4 + 30) & 0x1F));
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 2u:
        v2 = v7 + v8;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 3u:
        v2 = v7 & v8;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 4u:
        v2 = v7 | v8;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 5u:
        v2 = v7 ^ v8;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 6u:
        v2 = ~v8;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 7u:
        if ( v7 == (unsigned __int16)v8 )
          v2 = -1;
        else
          v2 = 0;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 8u:
        if ( (__int16)v7 >= (__int16)v8 )
          v2 = 0;
        else
          v2 = -1;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 9u:
        v2 = v7 >> (v8 & 0xF);
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 0xAu:
        v2 = v8 - 1;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 0xBu:
        v2 = *((unsigned __int16 *)v29 + (((_BYTE)v3 - 1) & 0x1F));
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 0xCu:
        if ( (unsigned __int16)v8 < 0x2000u )
          goto LABEL_51;
        v13 = (unsigned __int16)v8 >> 1;
        if ( BYTE1(v8) > 0x2Au )
        {
          v2 = word_A7DA[v13 - 5504];
          if ( (v9 & 0x8000) == 0 )
          {
LABEL_52:
            v14 = v10 & ((unsigned __int8)(v9 & 0x80) >> 7);
            v15 = v6 & 0xFFFFE000;
            if ( !v15 )
              goto LABEL_70;
            goto LABEL_56;
          }
        }
        else
        {
          v2 = *((unsigned __int16 *)&v27 + v13 - 4096);
          if ( (v9 & 0x8000) == 0 )
            goto LABEL_52;
        }
LABEL_55:
        v14 = 1;
        v15 = v6 & 0xFFFFE000;
        if ( !v15 )
          goto LABEL_70;
LABEL_56:
        if ( (_WORD)v8 )
          v16 = 0;
        else
          v16 = v15 == 0x2000;
        v17 = v16;
        if ( v15 == 0x4000 || v17 )
        {
LABEL_70:
          v18 = 2 * (v9 & 0x1FFF);
          if ( !v10 )
            goto LABEL_71;
LABEL_68:
          v4 += (int)(v9 << 30) >> 30;
          v3 += (unsigned __int8)((unsigned int)(char)(16 * v9) >> 6);
          v19 = (v9 >> 6) & 1;
          v20 = v8;
          if ( !v14 )
            goto LABEL_76;
LABEL_75:
          *((_WORD *)v30 + (((_BYTE)v4 + 30) & 0x1F)) = v8;
          goto LABEL_76;
        }
        v18 = *((_WORD *)v29 + (((_BYTE)v3 - 1) & 0x1F)) & 0x3FFF;
        if ( (v10 & ((unsigned __int16)(v9 & 0x1000) >> 12)) == 0 )
          v18 = v5 + 2;
        if ( (v9 & 0x8000) == 0 )
        {
          if ( v10 )
            goto LABEL_68;
LABEL_71:
          v4 -= v15 == 0x2000;
          if ( v15 == 0x4000 )
          {
            ++v3;
            v20 = v5 + 2;
            v19 = 1;
            if ( !v14 )
              goto LABEL_76;
          }
          else
          {
            v19 = 0;
            v20 = v18;
            if ( !v14 )
              goto LABEL_76;
          }
          goto LABEL_75;
        }
        v19 = 0;
        ++v4;
        v20 = v18;
        if ( v14 )
          goto LABEL_75;
LABEL_76:
        if ( v19 )
        {
          *((_WORD *)v29 + (((_BYTE)v3 - 1) & 0x1F)) = v20;
          if ( (v10 & ((unsigned __int8)(v9 & 0x20) >> 5)) == 0 )
            goto LABEL_2;
        }
        else if ( (v10 & ((unsigned __int8)(v9 & 0x20) >> 5)) == 0 )
        {
          goto LABEL_2;
        }
        v21 = (unsigned __int16)v8 >> 1;
        if ( v21 == 0x2000 )
          goto LABEL_2;
        if ( v21 != 10240 )
        {
          if ( (unsigned __int16)v8 >= 0x2000u )
          {
            if ( BYTE1(v8) >= 0x2Bu )
              v22 = (__int128 *)0x7CDA;
            else
              v22 = &v27 - 512;
            *((_WORD *)v22 + v21) = v7;
          }
LABEL_2:
          v5 = v18 & 0x3FFF;
          continue;
        }
        v23 = v28;
        *(_OWORD *)result = v27;
        *(_OWORD *)(result + 16) = v23;
        v24 = *(unsigned __int8 **)(a2 + 16);
        v25 = *v24;
        if ( v25 == 95 )
        {
          if ( v24[1] == 36 && v24[2] == 3 )
          {
            v26 = 4 * (v24[3] == 213);
            LOBYTE(v25) = v24[v26];
          }
          else
          {
            v26 = 0;
            LOBYTE(v25) = 95;
          }
        }
        else
        {
          v26 = 0;
        }
        *(_BYTE *)result ^= v25;
        *(_BYTE *)(result + 4) ^= v24[v26 | 1LL];
        *(_BYTE *)(result + 8) ^= v24[v26 | 2LL];
        *(_BYTE *)(result + 12) ^= v24[v26 | 3LL];
        return result;
      case 0xDu:
        v2 = v7 << (v8 & 0xF);
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 0xEu:
        v2 = v4;
        if ( (v9 & 0x8000) != 0 )
          goto LABEL_55;
        goto LABEL_52;
      case 0xFu:
        if ( v7 >= (unsigned __int16)v8 )
          v2 = 0;
        else
          v2 = -1;
        goto LABEL_51;
      default:
LABEL_51:
        if ( (v9 & 0x8000) == 0 )
          goto LABEL_52;
        goto LABEL_55;
    }
  }
}



/********************************************************************************/
Function: sub_D4C
/********************************************************************************/

long double __fastcall sub_D4C(__int64 a1)
{
  long double result; // q0

  *(_QWORD *)(a1 + 48) = 0;
  *(_OWORD *)(a1 + 16) = 0u;
  *(_OWORD *)(a1 + 32) = 0u;
  *(_OWORD *)a1 = 0u;
  *(_OWORD *)&result = 0u;
  return result;
}



/********************************************************************************/
Function: sub_D60
/********************************************************************************/

__int64 __fastcall sub_D60(_DWORD *a1, _DWORD *a2)
{
  a1[6] = *a2;
  a1[7] = a2[1];
  a1[8] = a2[2];
  a1[9] = a2[3];
  a1[10] = a2[4];
  a1[11] = a2[5];
  a1[12] = a2[6];
  a1[13] = a2[7];
  return 0;
}



/********************************************************************************/
Function: sub_DAC
/********************************************************************************/

__int64 __fastcall sub_DAC(__int64 *a1, __int64 a2, char *a3, _BYTE *a4)
{
  __int64 v5; // x9
  __int64 *v6; // x10
  __int64 *v7; // x11
  char v8; // w12
  char v9; // t1
  unsigned int v10; // w12
  unsigned int v11; // w13
  int v12; // w0
  int v13; // w14
  unsigned int v14; // w15
  unsigned int v15; // w16
  unsigned int v16; // w17
  int v17; // w6
  unsigned int v18; // w5
  unsigned int v19; // w4
  int v20; // w6

  v6 = a1 + 2;
  v5 = *a1;
  if ( a2 )
  {
    v7 = a1 + 3;
    do
    {
      --a2;
      if ( !v5 )
      {
        v10 = *((_DWORD *)a1 + 2);
        v11 = *((_DWORD *)a1 + 3);
        v12 = -2;
        v13 = -3;
        v14 = v11;
        v15 = v10;
        do
        {
          v16 = v12 + 2;
          v13 += 4;
          v17 = (v15 << 6) ^ (v15 >> 8);
          v18 = v15 + v17;
          v19 = v14 + *((_DWORD *)v7 + ((v12 + 2) & 6));
          v14 = v12 + 2 + v15 + v17 + v19;
          v20 = v19 + *((_DWORD *)v7 + (((_BYTE)v12 + 3) & 7)) + v17 + ((v14 << 6) ^ (v14 >> 8)) + 2 * v15;
          v12 = v16;
          v15 = v13 + v20;
        }
        while ( v16 < 0x3E );
        *((_DWORD *)a1 + 4) = v20 + v13;
        *((_DWORD *)a1 + 5) = v19 + v18 + v16;
        *((_DWORD *)a1 + 3) = v11 + 1;
        if ( v11 == -1 )
          *((_DWORD *)a1 + 2) = v10 + 1;
      }
      v8 = *((_BYTE *)v6 + v5);
      v9 = *a3++;
      v5 = ((_BYTE)v5 + 1) & 7;
      *a4++ = v8 ^ v9;
    }
    while ( a2 );
  }
  *a1 = v5;
  return 0;
}



/********************************************************************************/
Function: sub_E8C
/********************************************************************************/

__int64 __fastcall sub_E8C(__int64 a1, _QWORD *a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 v5; // x8
  _QWORD *v8; // x21
  __int64 v10; // x24
  __int64 v11; // t1
  __int64 v12; // x25
  unsigned __int8 *v13; // x23
  unsigned __int8 *v14; // x1

  *(_QWORD *)(a1 + 1032) = a4;
  *(_QWORD *)a1 = 0;
  *(_OWORD *)(a1 + 1056) = 0u;
  *(_OWORD *)(a1 + 1040) = 0u;
  v5 = *a2;
  if ( *a2 )
  {
    v8 = a2;
    v10 = 0;
    do
    {
      if ( v5 == 1 )
      {
        if ( v10 == 8 )
          return 0;
        v12 = *(_QWORD *)(a5 + 8);
        if ( !v12 )
          return 0;
        v13 = (unsigned __int8 *)(a3 + v8[1]);
        while ( 1 )
        {
          v14 = *(unsigned __int8 **)(v12 + 8);
          if ( *v14 == 47 )
            v14 = sub_748(*(unsigned __int8 **)(v12 + 8), 0x2Fu) + 1;
          if ( !(unsigned int)sub_720(v13, v14) )
            break;
          v12 = *(_QWORD *)(v12 + 24);
          if ( !v12 )
            return 0;
        }
        if ( (sub_10A8(a1 + (v10 << 7) + 8, *(_QWORD *)(v12 + 16), *(_QWORD *)v12) & 1) == 0 )
          return 0;
        v10 = *(_QWORD *)a1 + 1LL;
        *(_QWORD *)a1 = v10;
      }
      v11 = v8[2];
      v8 += 2;
      v5 = v11;
    }
    while ( v11 );
  }
  return 1;
}



/********************************************************************************/
Function: sub_F88
/********************************************************************************/

__int64 (__fastcall *__fastcall sub_F88(_QWORD *a1, __int64 a2))(unsigned __int64, __int64 **)
{
  unsigned __int64 v2; // x8
  __int64 v5; // x22
  _QWORD *i; // x20
  __int64 v7; // x0
  __int64 (__fastcall *result)(unsigned __int64, __int64 **); // x0
  char v9; // w8
  __int64 **v10; // x1
  __int64 **v11; // x19
  __int64 (__fastcall *v12)(unsigned __int64, __int64 **); // x2
  __int64 *v13; // x0
  __int64 v14; // x0
  __int64 *v15; // x8
  __int64 (__fastcall *v16)(unsigned __int64, __int64 **); // [xsp+18h] [xbp-18h]

  v2 = *a1;
  if ( !*a1 )
    return nullptr;
  v5 = 0;
  for ( i = a1 + 1; !*i; i += 16 )
  {
LABEL_3:
    if ( ++v5 >= v2 )
      return nullptr;
  }
  v7 = sub_1A70(i, a2);
  if ( !v7 )
  {
    v2 = *a1;
    goto LABEL_3;
  }
  v9 = *(_BYTE *)(v7 + 4);
  result = (__int64 (__fastcall *)(unsigned __int64, __int64 **))(*(_QWORD *)(v7 + 8) + *i);
  if ( (v9 & 0xF) == 0xA )
  {
    v10 = (__int64 **)(a1 + 129);
    v11 = v10;
    v12 = result;
    if ( *((_BYTE *)v10 + 32) )
    {
      return (__int64 (__fastcall *)(unsigned __int64, __int64 **))result(
                                                                     (unsigned __int64)v10[2] | 0x4000000000000000LL,
                                                                     v10 + 1);
    }
    else
    {
      v13 = *v10;
      v16 = v12;
      v10[1] = &qword_18;
      v14 = sub_232C(v13, 16);
      v15 = *v11;
      v11[2] = (__int64 *)v14;
      v11[3] = (__int64 *)sub_232C(v15, 26);
      *((_BYTE *)v11 + 32) = 1;
      return (__int64 (__fastcall *)(unsigned __int64, __int64 **))v16(
                                                                     (unsigned __int64)v11[2] | 0x4000000000000000LL,
                                                                     v11 + 1);
    }
  }
  return result;
}



/********************************************************************************/
Function: sub_10A8
/********************************************************************************/

bool __fastcall sub_10A8(__int64 a1, __int64 *a2, __int64 a3)
{
  __int64 v3; // x16
  unsigned int *v4; // x13
  unsigned __int64 v5; // x9
  __int64 v6; // x10
  __int64 v7; // x12
  __int64 v8; // t1
  __int64 v9; // x17
  unsigned int *v10; // x15
  __int64 v11; // x15
  __int64 v12; // x16
  __int64 v13; // x3
  unsigned int v14; // w16
  __int64 v15; // x4
  unsigned int v16; // w17
  unsigned int *v17; // x17
  unsigned int v18; // w5
  __int64 v19; // x6
  int32x4_t v20; // q0
  unsigned __int64 v21; // x19
  uint32x4_t *v22; // x5
  unsigned __int64 v23; // x20
  uint32x4_t v24; // q1
  uint32x4_t v25; // q2
  uint32x4_t v26; // q3
  unsigned int *v27; // x4
  __int64 v28; // x15
  unsigned int *v29; // x3
  unsigned int v30; // w4
  unsigned int v31; // t1
  unsigned int v32; // w15
  unsigned int v33; // w16
  _BOOL8 result; // x0

  *(_QWORD *)(a1 + 112) = 0;
  *(_QWORD *)(a1 + 120) = 0;
  *(_QWORD *)(a1 + 104) = 0;
  *(_QWORD *)a1 = a3;
  *(_OWORD *)(a1 + 24) = 0u;
  *(_OWORD *)(a1 + 40) = 0u;
  *(_OWORD *)(a1 + 56) = 0u;
  *(_OWORD *)(a1 + 72) = 0u;
  *(_OWORD *)(a1 + 84) = 0u;
  *(_OWORD *)(a1 + 8) = 0u;
  v3 = *a2;
  if ( !*a2 )
    return 0;
  v4 = nullptr;
  v5 = 0;
  v6 = 0;
  v7 = 0;
  while ( 2 )
  {
    v9 = a2[1];
    v10 = (unsigned int *)(v9 + a3);
    switch ( v3 )
    {
      case 2LL:
        *(_QWORD *)(a1 + 40) = v9;
        goto LABEL_4;
      case 3LL:
      case 7LL:
      case 8LL:
      case 9LL:
      case 11LL:
      case 12LL:
      case 13LL:
      case 14LL:
      case 15LL:
      case 16LL:
      case 17LL:
      case 18LL:
      case 19LL:
      case 20LL:
      case 21LL:
      case 22LL:
        goto LABEL_4;
      case 4LL:
        v5 = (unsigned __int64)(v10 + 2);
        v12 = *v10;
        v11 = v10[1];
        *(_QWORD *)(a1 + 48) = v5;
        *(_QWORD *)(a1 + 56) = v12;
        *(_QWORD *)(a1 + 64) = v5 + 4 * v12;
        *(_QWORD *)(a1 + 72) = v11;
        goto LABEL_4;
      case 5LL:
        v6 = v9 + a3;
        *(_QWORD *)(a1 + 16) = v10;
        goto LABEL_4;
      case 6LL:
        v7 = v9 + a3;
        *(_QWORD *)(a1 + 8) = v10;
        goto LABEL_4;
      case 10LL:
        *(_QWORD *)(a1 + 24) = v9;
        goto LABEL_4;
      case 23LL:
        *(_QWORD *)(a1 + 32) = v10;
        goto LABEL_4;
      default:
        if ( v3 != 1879047925 )
          goto LABEL_4;
        *(_DWORD *)(a1 + 80) = 0;
        v13 = *v10;
        *(_DWORD *)(a1 + 84) = v13;
        v14 = v10[1];
        *(_DWORD *)(a1 + 88) = v14;
        v15 = v10[2];
        *(_DWORD *)(a1 + 92) = v15 - 1;
        v4 = &v10[2 * v15 + 4];
        v16 = v10[3];
        *(_QWORD *)(a1 + 104) = v10 + 4;
        *(_QWORD *)(a1 + 112) = v4;
        *(_DWORD *)(a1 + 96) = v16;
        v17 = &v4[v13];
        *(_QWORD *)(a1 + 120) = v17;
        if ( !(_DWORD)v13 )
          goto LABEL_4;
        v18 = *v4;
        if ( (_DWORD)v13 == 1 )
          goto LABEL_23;
        if ( (unsigned int)v13 >= 9 )
        {
          v20 = vdupq_n_s32(v18);
          v21 = (v13 - 1) & 0xFFFFFFFFFFFFFFF8LL;
          v19 = v21 | 1;
          v22 = (uint32x4_t *)&v10[2 * v15 + 9];
          v23 = v21;
          v24 = v20;
          do
          {
            v25 = v22[-1];
            v26 = *v22;
            v22 += 2;
            v23 -= 8LL;
            v20 = vmaxq_u32(v25, v20);
            v24 = vmaxq_u32(v26, v24);
          }
          while ( v23 );
          v18 = vmaxvq_u32(vmaxq_u32(v20, v24));
          if ( v13 - 1 == v21 )
            goto LABEL_23;
        }
        else
        {
          v19 = 1;
        }
        v27 = &v10[2 * v15 + v19];
        v28 = v13 - v19;
        v29 = v27 + 4;
        do
        {
          v31 = *v29++;
          v30 = v31;
          if ( v31 > v18 )
            v18 = v30;
          --v28;
        }
        while ( v28 );
LABEL_23:
        v32 = v18 - v14;
        do
          v33 = v17[v32++];
        while ( (v33 & 1) == 0 );
        *(_DWORD *)(a1 + 80) = v32;
LABEL_4:
        v8 = a2[2];
        a2 += 2;
        v3 = v8;
        if ( v8 )
          continue;
        result = 0;
        if ( v7 )
        {
          if ( v6 )
            return (v5 | (unsigned __int64)v4) != 0;
        }
        return result;
    }
  }
}



/********************************************************************************/
Function: sub_1290
/********************************************************************************/

__int64 __fastcall sub_1290(int *a1, unsigned __int64 a2, __int64 a3, unsigned __int64 *a4)
{
  __int64 v4; // x29
  __int64 v5; // x30
  int v8; // w20
  char *v9; // x25
  __int64 v11; // x8
  __int64 v12; // x9
  size_t v13; // x1
  unsigned __int64 v14; // x0
  unsigned __int64 v15; // x8
  __int64 v16; // x9
  unsigned __int64 v17; // x8
  __int64 v18; // x9
  unsigned __int64 v19; // x8
  unsigned __int64 v20; // x10
  unsigned __int64 v21; // x10
  unsigned __int64 v22; // x28
  size_t v23; // x1
  bool v24; // w26
  unsigned __int64 v25; // x29
  char v26; // w21
  __int64 v27; // x20
  __int64 v28; // x12
  char *v29; // x22
  unsigned __int64 v30; // x8
  void *v31; // x23
  size_t v32; // x24
  unsigned __int64 v33; // x0
  char *v35; // x27
  char *v36; // x25
  __int64 v37; // x20
  __int64 v38; // x22
  unsigned int v39; // w8
  int v40; // w10
  unsigned __int64 *v41; // x9
  int v42; // w0
  unsigned __int8 *v43; // x9
  __int16 v44; // t1
  int v45; // w0
  __int64 v46; // [xsp+10h] [xbp-110h]
  __int64 v47; // [xsp+18h] [xbp-108h]
  __int64 v48; // [xsp+20h] [xbp-100h]
  __int64 v49; // [xsp+28h] [xbp-F8h] BYREF
  int v50; // [xsp+30h] [xbp-F0h]
  _DWORD v51[8]; // [xsp+60h] [xbp-C0h] BYREF
  _DWORD v52[6]; // [xsp+80h] [xbp-A0h] BYREF
  unsigned int v53; // [xsp+98h] [xbp-88h]
  unsigned int v54; // [xsp+9Ch] [xbp-84h]
  unsigned int v55; // [xsp+A0h] [xbp-80h]
  _DWORD v56[2]; // [xsp+A8h] [xbp-78h] BYREF
  unsigned int v57; // [xsp+B0h] [xbp-70h]
  int v58; // [xsp+B4h] [xbp-6Ch]
  int v59; // [xsp+B8h] [xbp-68h]
  unsigned int v60; // [xsp+BCh] [xbp-64h]
  __int64 v61; // [xsp+C0h] [xbp-60h]
  __int64 v62; // [xsp+C8h] [xbp-58h]

  if ( a2 < 0x29 )
    return 0;
  v61 = v4;
  v62 = v5;
  v8 = *a1;
  v9 = (char *)(a1 + 1);
  sub_918((__int64)v51, a3);
  sub_D4C((__int64)&v49);
  v50 = v8;
  sub_D60(&v49, v51);
  sub_DAC(&v49, 36, v9, v52);
  v11 = v52[0];
  a1[9] = 0;
  v12 = v54;
  v13 = v54 + v11;
  *(_OWORD *)(a1 + 1) = 0u;
  *(_OWORD *)(a1 + 5) = 0u;
  a4[1] = v13;
  v14 = (unsigned __int64)linux_eabi_syscall(__NR_mmap, nullptr, v13, 0, 34, -1, 0);
  if ( v14 > 0xFFFFFFFFFFFFF000LL )
    v14 = -1;
  *a4 = v14;
  if ( v14 == -1 )
    return 0;
  v47 = v12 - 1;
  v15 = v14 % v12;
  v46 = -v12;
  v16 = (v14 + v12 - 1) & -v12;
  if ( v15 )
    v17 = v16;
  else
    v17 = v14;
  v18 = v52[5];
  v19 = v17 - v52[1];
  v20 = v19 + v52[4];
  a4[2] = v19;
  a4[3] = v20;
  if ( (_DWORD)v18 )
  {
    v21 = v53;
    if ( v53 )
    {
      a4[4] = v19 + v18;
      a4[5] = v21;
    }
  }
  v22 = v55;
  if ( v55 >= 5 )
  {
    if ( !v14 )
      goto LABEL_41;
    v23 = a4[1];
    if ( !v23 )
      goto LABEL_41;
    goto LABEL_40;
  }
  if ( !v55 )
    return 1;
  v24 = 0;
  v25 = 0;
  v26 = 1;
  v27 = 36;
  do
  {
    v29 = &v9[v27];
    sub_DAC(&v49, 24, &v9[v27], v56);
    *((_QWORD *)v29 + 1) = 0;
    *((_QWORD *)v29 + 2) = 0;
    *(_QWORD *)v29 = 0;
    v30 = a4[2] + v56[0];
    v31 = (void *)(v30 & v46);
    v32 = ((v30 + v47 + v56[1]) & v46) - (v30 & v46);
    v33 = linux_eabi_syscall(__NR_mprotect, (void *)(v30 & v46), v32, 3);
    if ( v33 > 0xFFFFFFFFFFFFF000LL || (unsigned int)v33 != 0 )
      break;
    v35 = v9;
    v36 = &v9[v27 + 24];
    v48 = v27 + 24;
    sub_DAC(&v49, v60, v36, v36);
    v37 = (v26 & 1) != 0 ? (int)sub_1C5C(v36, a4[2] + v56[0], v60, v57) : 0LL;
    v38 = v60;
    sub_63C((unsigned __int64)v36, 0, v60);
    v39 = v57;
    if ( v37 != v57 )
      break;
    v9 = v35;
    v40 = v58;
    v41 = &a4[3 * v25];
    v41[6] = (unsigned __int64)v31;
    v41[7] = v32;
    *((_DWORD *)v41 + 16) = v40;
    if ( (v40 & 4) != 0 )
    {
      v42 = linux_eabi_syscall(__NR_prctl, 1398164801, nullptr, v31);
      v37 = v57;
      v39 = v57;
    }
    if ( v39 )
    {
      v39 = 0;
      v28 = v48;
      v43 = (unsigned __int8 *)(a4[2] + v56[0]);
      do
      {
        v44 = *v43++;
        --v37;
        v39 = (unsigned __int16)(((v39 >> 1) | ((_WORD)v39 << 15)) + v44);
      }
      while ( v37 );
    }
    else
    {
      v28 = v48;
    }
    ++v25;
    v27 = v28 + v38;
    v26 &= v39 == v59;
    v24 = v25 >= v22;
  }
  while ( v25 != v22 );
  if ( v24 )
    return 1;
  v14 = *a4;
  if ( *a4 )
  {
    v23 = a4[1];
    if ( v23 )
LABEL_40:
      v45 = linux_eabi_syscall(__NR_munmap, (void *)v14, v23);
  }
LABEL_41:
  *a4 = 0;
  a4[1] = 0;
  return 0;
}



/********************************************************************************/
Function: sub_15BC
/********************************************************************************/

int __fastcall sub_15BC(__int64 a1)
{
  void *v2; // x0
  size_t v3; // x1

  v2 = *(void **)a1;
  if ( v2 )
  {
    v3 = *(_QWORD *)(a1 + 8);
    if ( v3 )
      LODWORD(v2) = linux_eabi_syscall(__NR_munmap, v2, v3);
  }
  *(_QWORD *)a1 = 0;
  *(_QWORD *)(a1 + 8) = 0;
  return (int)v2;
}



/********************************************************************************/
Function: sub_15E0
/********************************************************************************/

int __fastcall sub_15E0(__int64 a1)
{
  void *v2; // x0
  size_t v3; // x1
  int v4; // w0
  size_t v5; // x1
  int v6; // w0
  size_t v7; // x1
  int v8; // w0
  size_t v9; // x1

  v2 = *(void **)(a1 + 48);
  if ( v2 )
  {
    v3 = *(_QWORD *)(a1 + 56);
    if ( v3 )
    {
      v4 = linux_eabi_syscall(__NR_mprotect, v2, v3, *(_DWORD *)(a1 + 64));
      v2 = *(void **)(a1 + 72);
      if ( v2 )
      {
        v5 = *(_QWORD *)(a1 + 80);
        if ( v5 )
        {
          v6 = linux_eabi_syscall(__NR_mprotect, v2, v5, *(_DWORD *)(a1 + 88));
          v2 = *(void **)(a1 + 96);
          if ( v2 )
          {
            v7 = *(_QWORD *)(a1 + 104);
            if ( v7 )
            {
              v8 = linux_eabi_syscall(__NR_mprotect, v2, v7, *(_DWORD *)(a1 + 112));
              v2 = *(void **)(a1 + 120);
              if ( v2 )
              {
                v9 = *(_QWORD *)(a1 + 128);
                if ( v9 )
                  LODWORD(v2) = linux_eabi_syscall(__NR_mprotect, v2, v9, *(_DWORD *)(a1 + 136));
              }
            }
          }
        }
      }
    }
  }
  return (int)v2;
}



/********************************************************************************/
Function: sub_1658
/********************************************************************************/

int __fastcall sub_1658(__int64 a1)
{
  void *v2; // x0
  size_t v3; // x1

  v2 = *(void **)(a1 + 32);
  if ( v2 )
  {
    v3 = *(_QWORD *)(a1 + 40);
    if ( v3 )
      LODWORD(v2) = linux_eabi_syscall(__NR_mprotect, v2, v3, 1);
  }
  return (int)v2;
}



/********************************************************************************/
Function: sub_167C
/********************************************************************************/

__int64 __fastcall sub_167C(__int64 *a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v4; // x12
  __int64 v5; // x11
  unsigned __int64 v7; // x24
  __int64 v8; // x25
  __int64 v9; // x28
  __int64 v10; // x20
  unsigned __int64 *v11; // x21
  __int64 v12; // x27
  __int64 v13; // x26
  __int64 v14; // x23
  __int64 v15; // x22
  __int64 *v16; // x9
  __int64 v17; // t1
  __int64 v18; // kr08_8
  _QWORD v20[2]; // [xsp+0h] [xbp-4A0h] BYREF
  _BYTE v21[1072]; // [xsp+10h] [xbp-490h] BYREF

  v5 = *a1;
  if ( *a1 )
  {
    v7 = 0;
    v8 = 0;
    v9 = 0;
    v10 = 0;
    v11 = nullptr;
    v12 = 0;
    v13 = 0;
    v14 = 0;
    v15 = 0;
    v16 = a1 + 2;
    do
    {
      v18 = v4;
      v4 = *(v16 - 1);
      switch ( v5 )
      {
        case 2LL:
          v14 = *(v16 - 1);
          break;
        case 5LL:
          v8 = v4 + a2;
          break;
        case 6LL:
          v7 = v4 + a2;
          break;
        case 7LL:
          v13 = v4 + a2;
          break;
        case 8LL:
          v12 = *(v16 - 1);
          break;
        case 10LL:
          v9 = *(v16 - 1);
          break;
        case 23LL:
          v15 = v4 + a2;
          break;
        case 35LL:
          v10 = *(v16 - 1);
          break;
        case 36LL:
          v11 = (unsigned __int64 *)(v4 + a2);
          break;
        case 37LL:
          if ( v4 != 8 )
            return 0;
          break;
        default:
          v4 = v18;
          break;
      }
      v17 = *v16;
      v16 += 2;
      v5 = v17;
    }
    while ( v17 );
  }
  else
  {
    v15 = 0;
    v14 = 0;
    v13 = 0;
    v12 = 0;
    v11 = nullptr;
    v10 = 0;
    v9 = 0;
    v8 = 0;
    v7 = 0;
  }
  sub_E8C((__int64)v21, a1, v8, a3, a4);
  v20[0] = v7;
  v20[1] = v8;
  if ( (sub_1820(a2, v13, v12, v21, v20) & 1) == 0 || (sub_1820(a2, v15, v14, v21, v20) & 1) == 0 )
    return 0;
  sub_63C(v7, 0, v9 + v8 - v7);
  sub_19EC(a2, v11, v10);
  return 1;
}



/********************************************************************************/
Function: sub_1820
/********************************************************************************/

bool __fastcall sub_1820(__int64 a1, __int64 *a2, unsigned __int64 a3)
{
  bool v3; // w26
  __int64 *v4; // x19
  unsigned __int64 v6; // x23
  unsigned __int64 v7; // x24
  unsigned __int64 v8; // x25
  __int64 v9; // x9
  unsigned __int64 v10; // x0
  __int64 v11; // x10
  __int64 v12; // x8

  v3 = 1;
  if ( a2 && a3 >= 0x18 )
  {
    v4 = a2;
    v3 = 0;
    v6 = 0;
    v7 = a3 / 0x18;
    if ( a3 / 0x18 <= 1 )
      v8 = 1;
    else
      v8 = a3 / 0x18;
    do
    {
      v10 = v4[1];
      if ( HIDWORD(v10) )
      {
        if ( (sub_194C() & 1) == 0 )
          return v3;
        v10 = v4[1];
        v11 = v4[2];
        v12 = *v4;
        if ( (unsigned int)(v10 - 1025) < 2 )
        {
LABEL_6:
          v9 = v11;
          goto LABEL_7;
        }
      }
      else
      {
        v11 = v4[2];
        v12 = *v4;
        if ( (unsigned int)(v10 - 1025) < 2 )
          goto LABEL_6;
      }
      if ( (_DWORD)v10 == 257 )
      {
        v9 = v11 + *(_QWORD *)(a1 + v12);
      }
      else
      {
        if ( (_DWORD)v10 != 1027 || HIDWORD(v10) )
        {
          *v4 = 0;
          v4[1] = 0;
          v4[2] = 0;
          return v3;
        }
        v9 = v11 + a1;
      }
LABEL_7:
      ++v6;
      *(_QWORD *)(a1 + v12) = v9;
      *v4 = 0;
      v4[1] = 0;
      v4[2] = 0;
      v4 += 3;
      v3 = v6 >= v7;
    }
    while ( v8 != v6 );
  }
  return v3;
}



/********************************************************************************/
Function: sub_194C
/********************************************************************************/

__int64 __fastcall sub_194C(
        int a1,
        unsigned int a2,
        _QWORD *a3,
        __int64 a4,
        __int64 a5,
        __int64 (__fastcall **a6)(unsigned __int64, __int64 **))
{
  __int64 (__fastcall *v10)(unsigned __int64, __int64 **); // x0

  v10 = sub_F88(a3, a5 + *(unsigned int *)(a4 + 24LL * a2));
  if ( !v10 )
  {
    if ( (*(_BYTE *)(a4 + 24LL * a2 + 4) & 0xF0) != 0x20 )
      return 0;
    v10 = nullptr;
    if ( (unsigned int)(a1 - 1025) >= 3 && a1 != 257 )
      return 0;
  }
  *a6 = v10;
  return 1;
}



/********************************************************************************/
Function: sub_19EC
/********************************************************************************/

__int64 __fastcall sub_19EC(__int64 result, unsigned __int64 *a2, __int64 a3)
{
  unsigned __int64 v3; // x9
  unsigned __int64 *v4; // x8
  unsigned __int64 v5; // x10
  _QWORD *v6; // x11
  bool v7; // cc

  if ( a2 && (__int64)(a3 & 0xFFFFFFFFFFFFFFF8LL) >= 1 )
  {
    v3 = 0;
    v4 = (unsigned __int64 *)((char *)a2 + (a3 & 0xFFFFFFFFFFFFFFF8LL));
    do
    {
      while ( 1 )
      {
        v5 = *a2;
        *a2++ = 0;
        if ( (v5 & 1) != 0 )
          break;
        v3 = v5 + 8;
        *(_QWORD *)(v5 + result) += result;
        if ( a2 >= v4 )
          return result;
      }
      v6 = (_QWORD *)(result + v3);
      do
      {
        if ( (v5 & 2) != 0 )
          *v6 += result;
        v7 = v5 > 1;
        ++v6;
        v5 >>= 1;
      }
      while ( v7 );
      v3 += 504LL;
    }
    while ( a2 < v4 );
  }
  return result;
}



/********************************************************************************/
Function: sub_1A70
/********************************************************************************/

unsigned int *__fastcall sub_1A70(__int64 a1, unsigned __int8 *a2)
{
  __int64 v3; // x8
  int v5; // w11
  unsigned __int64 v6; // x9
  unsigned __int8 *v7; // x10
  unsigned int v8; // w9
  int v9; // t1
  __int64 v10; // x22
  __int64 v11; // x8
  int v12; // w9
  unsigned __int8 *v13; // x10
  unsigned int v14; // w22
  int v15; // t1
  __int64 v16; // x23
  __int64 v17; // x25
  unsigned int *v18; // x21
  unsigned int v19; // w9
  unsigned int v20; // w8
  __int64 v22; // x23
  int v23; // w24
  __int64 v24; // x25
  unsigned int v25; // w28
  int v26; // w27

  v3 = *(_QWORD *)(a1 + 48);
  if ( v3 )
  {
    v5 = *a2;
    if ( *a2 )
    {
      LODWORD(v6) = 0;
      v7 = a2 + 1;
      do
      {
        v8 = v5 + 16 * v6;
        v9 = *v7++;
        v5 = v9;
        v6 = v8 & 0xFFFFFFF ^ (16 * (v8 >> 28));
      }
      while ( v9 );
      v10 = *(unsigned int *)(v3 + 4 * (v6 % *(_QWORD *)(a1 + 56)));
      if ( !(_DWORD)v10 )
        return nullptr;
    }
    else
    {
      v10 = *(unsigned int *)(v3 - 4 * 0uLL / *(_QWORD *)(a1 + 56) * *(_QWORD *)(a1 + 56));
      if ( !(_DWORD)v10 )
        return nullptr;
    }
    v16 = *(_QWORD *)(a1 + 8);
    v17 = *(_QWORD *)(a1 + 16);
    while ( 1 )
    {
      v18 = (unsigned int *)(v16 + 24 * v10);
      if ( !(unsigned int)sub_720((unsigned __int8 *)(v17 + *v18), a2)
        && *(_WORD *)(v16 + 24 * v10 + 6)
        && (*(unsigned __int8 *)(v16 + 24 * v10 + 4) >> 4) - 1 < 2u )
      {
        break;
      }
      v10 = *(unsigned int *)(*(_QWORD *)(a1 + 64) + 4 * v10);
      if ( !(_DWORD)v10 )
        return nullptr;
    }
  }
  else
  {
    v11 = *(_QWORD *)(a1 + 112);
    if ( !v11 )
      return nullptr;
    v12 = *a2;
    if ( *a2 )
    {
      v13 = a2 + 1;
      v14 = 5381;
      do
      {
        v14 = 33 * v14 + v12;
        v15 = *v13++;
        v12 = v15;
      }
      while ( v15 );
    }
    else
    {
      v14 = 5381;
    }
    if ( (((1LL << ((unsigned __int64)v14 >> *(_DWORD *)(a1 + 96))) | (1LL << v14))
        & ~*(_QWORD *)(*(_QWORD *)(a1 + 104) + 8 * (*(unsigned int *)(a1 + 92) & ((unsigned __int64)v14 >> 6)))) != 0 )
      return nullptr;
    v19 = *(_DWORD *)(a1 + 88);
    v20 = *(_DWORD *)(v11 + 4LL * (v14 % *(_DWORD *)(a1 + 84)));
    if ( v20 < v19 )
      return nullptr;
    v22 = *(_QWORD *)(a1 + 8);
    v23 = -v19;
    v24 = *(_QWORD *)(a1 + 120);
    while ( 1 )
    {
      v25 = v20;
      v26 = *(_DWORD *)(v24 + 4LL * (v23 + v20));
      if ( (v26 ^ v14) <= 1 )
      {
        v18 = (unsigned int *)(v22 + 24LL * v20);
        if ( !(unsigned int)sub_720((unsigned __int8 *)(*(_QWORD *)(a1 + 16) + *v18), a2)
          && (*(unsigned __int8 *)(v22 + 24LL * v25 + 4) >> 4) - 1 <= 1u
          && *(_WORD *)(v22 + 24LL * v25 + 6) )
        {
          break;
        }
      }
      v20 = v25 + 1;
      if ( (v26 & 1) != 0 )
        return nullptr;
    }
  }
  return v18;
}



/********************************************************************************/
Function: sub_1C5C
/********************************************************************************/

__int64 __fastcall sub_1C5C(unsigned __int8 *a1, unsigned __int64 a2, int a3, unsigned int a4)
{
  unsigned int v4; // w8
  unsigned __int16 *v6; // x10
  unsigned __int64 v7; // x9
  unsigned __int64 v8; // x13
  unsigned __int64 v9; // x14
  unsigned __int64 v10; // x15
  unsigned __int64 v11; // x16
  unsigned __int64 v12; // x17
  unsigned __int8 *v13; // x1
  unsigned __int64 v14; // x8
  unsigned __int64 v15; // x7
  unsigned __int8 *v16; // x20
  unsigned __int64 v17; // x2
  __int64 v18; // x2
  unsigned __int64 v19; // x22
  __int64 v20; // x21
  __int64 v21; // x23
  unsigned __int64 v22; // x20
  unsigned __int16 *v23; // x21
  unsigned __int64 v25; // x2
  unsigned __int64 v26; // x2
  __int64 v27; // x23
  __int64 v28; // x22
  __int64 v29; // x25
  unsigned __int8 *v30; // x2
  _QWORD *v31; // x22
  _OWORD *v32; // x8
  __int128 *v33; // x1
  __int128 v34; // q0
  __int128 v35; // q1
  __int128 v36; // q0
  unsigned __int8 *v37; // x1
  __int64 v38; // x7
  unsigned __int64 v39; // x22
  unsigned int v40; // t1
  unsigned __int64 v41; // x2
  unsigned __int8 *v42; // x21
  __int64 v43; // t1
  unsigned int v44; // t1
  __int64 v45; // x8
  unsigned __int64 v46; // x7
  __int64 v47; // x23
  bool v48; // w21
  _QWORD *v49; // x2
  __int64 v50; // t1
  unsigned __int64 v51; // x22
  _QWORD *v52; // x21
  unsigned __int64 v53; // x7
  unsigned __int64 v54; // x21
  _QWORD *v55; // x7
  unsigned __int64 v56; // x21
  _QWORD *v57; // x21
  __int64 *v58; // x2
  __int64 v59; // t1
  _OWORD *v60; // x20
  __int64 v61; // x22
  __int64 v62; // x24
  __int128 *v63; // x2
  __int64 v64; // x24
  __int128 v65; // q0
  __int128 v66; // q1
  _DWORD *v67; // x8
  unsigned __int64 v68; // x22
  unsigned __int64 v69; // x24
  __int64 *v70; // x22
  _QWORD *v71; // x23
  char *v73; // x22
  _OWORD *v74; // x26
  __int64 v75; // x24
  __int128 *v76; // x27
  __int64 v77; // x23
  __int64 v78; // x28
  __int128 v79; // q0
  __int128 v80; // q1
  __int64 v81; // t1
  unsigned __int64 v82; // x22
  unsigned __int64 v83; // x7
  unsigned __int64 v84; // x23
  unsigned __int64 v85; // x7
  _BYTE *v86; // x20
  unsigned __int64 v87; // x24
  _OWORD *v88; // x26
  __int128 *v89; // x25
  unsigned __int64 v90; // x27
  __int128 v91; // q0
  __int128 v92; // q1
  unsigned __int64 v93; // x25
  __int64 *v94; // x2
  _QWORD *v95; // x21
  unsigned __int64 v96; // x24
  __int64 v97; // t1
  char v98; // t1

  v4 = -1;
  if ( !a1 || (a4 & 0x80000000) != 0 )
    return v4;
  if ( !a4 )
  {
    if ( a3 == 1 )
    {
      if ( *a1 )
        return (unsigned int)-1;
      else
        return 0;
    }
    return v4;
  }
  if ( !a3 )
    return v4;
  v6 = (unsigned __int16 *)&a1[a3];
  v7 = a2 + a4;
  v8 = (unsigned __int64)v6 - 15;
  v9 = v7 - 12;
  v10 = (unsigned __int64)(v6 - 4);
  v11 = (unsigned __int64)(v6 - 2);
  v12 = v7 - 7;
  v13 = a1;
  v14 = a2;
  while ( 1 )
  {
    v16 = v13 + 1;
    v15 = *v13;
    v17 = v15 >> 4;
    if ( (unsigned int)(v15 >> 4) == 15 )
    {
      if ( (unsigned __int64)v16 >= v8 )
      {
        LODWORD(v13) = (_DWORD)v13 + 1;
      }
      else
      {
        v18 = 0;
        if ( v8 >= (unsigned __int64)v16 )
          v19 = v8 - (_QWORD)v16;
        else
          v19 = 0;
        v20 = (__int64)(v13 + 2);
        while ( 1 )
        {
          v13 = v16 + 1;
          if ( !v19 )
            break;
          v21 = *v16;
          --v19;
          ++v20;
          ++v16;
          v18 += v21;
          if ( v21 != 255 )
          {
            if ( v18 == -1 )
              return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
            v17 = v18 + 15;
            if ( __CFADD__(v14, v17) || v17 > -v20 )
              return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
            v22 = v14 + v17;
            v23 = (unsigned __int16 *)&v13[v17];
            if ( v14 + v17 > v9 || (unsigned __int64)v23 > v10 )
              goto LABEL_107;
            goto LABEL_22;
          }
        }
      }
      return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
    }
    if ( v16 >= (unsigned __int8 *)v6 - 16 || v14 > v7 - 32 )
      break;
    v36 = *(_OWORD *)v16;
    v37 = &v16[v17];
    v22 = v14 + v17;
    v38 = v15 & 0xF;
    *(_OWORD *)v14 = v36;
    v40 = *(unsigned __int16 *)v37;
    v13 = v37 + 2;
    v39 = v40;
    v41 = v14 + v17 - v40;
    if ( (_DWORD)v38 == 15 || (unsigned int)v39 < 8 || v41 < a2 )
    {
      v42 = v13;
      if ( v38 == 15 )
        goto LABEL_40;
LABEL_36:
      v13 = v42;
LABEL_50:
      if ( v41 < a2 )
        return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
      if ( v39 <= 7 )
      {
        *(_DWORD *)v22 = 0;
        *(_BYTE *)v22 = *(_BYTE *)v41;
        *(_BYTE *)(v22 + 1) = *(_BYTE *)(v41 + 1);
        *(_BYTE *)(v22 + 2) = *(_BYTE *)(v41 + 2);
        *(_BYTE *)(v22 + 3) = *(_BYTE *)(v41 + 3);
        v67 = (_DWORD *)(v41 + dword_354[v39]);
        *(_DWORD *)(v22 + 4) = *v67;
        v49 = (_QWORD *)((char *)v67 - dword_334[v39]);
        v51 = v38 + 4;
        v52 = (_QWORD *)(v22 + 8);
        v14 = v22 + v38 + 4;
        if ( v14 <= v9 )
          goto LABEL_53;
LABEL_67:
        if ( v14 > v7 - 5 )
          return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
        if ( (unsigned __int64)v52 < v12 )
        {
          v68 = v22 + 16;
          if ( v12 > v22 + 16 )
            v68 = v7 - 7;
          v69 = v68 - v22 - 9;
          if ( v69 < 0x28 )
          {
            v70 = v49;
            v71 = v52;
            goto LABEL_84;
          }
          v71 = v52;
          v70 = v49;
          if ( v22 - (unsigned __int64)v49 + 8 < 0x20 )
            goto LABEL_119;
          v74 = (_OWORD *)(v22 + 24);
          v75 = (v69 >> 3) + 1;
          v76 = (__int128 *)(v49 + 2);
          v77 = v75 & 0x3FFFFFFFFFFFFFFCLL;
          v78 = v75 & 0x3FFFFFFFFFFFFFFCLL;
          v70 = &v49[v77];
          v71 = &v52[v77];
          do
          {
            v79 = *(v76 - 1);
            v80 = *v76;
            v76 += 2;
            v78 -= 4;
            *(v74 - 1) = v79;
            *v74 = v80;
            v74 += 2;
          }
          while ( v78 );
          if ( v75 != (v75 & 0x3FFFFFFFFFFFFFFCLL) )
          {
LABEL_119:
            do
            {
LABEL_84:
              v81 = *v70++;
              *v71++ = v81;
            }
            while ( (unsigned __int64)v71 < v12 );
          }
          v82 = v12 - (_QWORD)v52;
          v52 = (_QWORD *)(v7 - 7);
          v73 = (char *)v49 + v82;
          goto LABEL_86;
        }
        v73 = (char *)v49;
LABEL_86:
        if ( (unsigned __int64)v52 < v14 )
        {
          v83 = v38 + v22;
          if ( v12 <= v22 + 8 )
            v84 = v22 + 8;
          else
            v84 = v7 - 7;
          v85 = v83 - v84 + 4;
          if ( v85 < 8 )
          {
            v86 = v52;
            goto LABEL_105;
          }
          if ( v22 - (unsigned __int64)v49 + 8 < 0x20 )
          {
            v86 = v52;
            goto LABEL_105;
          }
          if ( v85 >= 0x20 )
          {
            v87 = v85 & 0xFFFFFFFFFFFFFFE0LL;
            v88 = v52 + 2;
            v89 = (__int128 *)((char *)v49 + v84 - v22 + 8);
            v90 = v85 & 0xFFFFFFFFFFFFFFE0LL;
            do
            {
              v91 = *(v89 - 1);
              v92 = *v89;
              v90 -= 32LL;
              v89 += 2;
              *(v88 - 1) = v91;
              *v88 = v92;
              v88 += 2;
            }
            while ( v90 );
            if ( v85 != v87 )
            {
              if ( (v85 & 0x18) == 0 )
              {
                v73 += v87;
                v86 = (char *)v52 + v87;
                goto LABEL_105;
              }
              goto LABEL_100;
            }
          }
          else
          {
            v87 = 0;
LABEL_100:
            v93 = v87 + v84 - v22;
            v86 = (char *)v52 + (v85 & 0xFFFFFFFFFFFFFFF8LL);
            v73 += v85 & 0xFFFFFFFFFFFFFFF8LL;
            v94 = (_QWORD *)((char *)v49 + v93 - 8);
            v95 = (_QWORD *)((char *)v52 + v87);
            v96 = v87 - (v85 & 0xFFFFFFFFFFFFFFF8LL);
            do
            {
              v97 = *v94++;
              v96 += 8LL;
              *v95++ = v97;
            }
            while ( v96 );
            if ( v85 != (v85 & 0xFFFFFFFFFFFFFFF8LL) )
            {
              do
              {
LABEL_105:
                v98 = *v73++;
                *v86++ = v98;
              }
              while ( (unsigned __int64)v86 < v14 );
            }
          }
        }
      }
      else
      {
        v50 = *(_QWORD *)v41;
        v49 = (_QWORD *)(v41 + 8);
        *(_QWORD *)v22 = v50;
        v51 = v38 + 4;
        v52 = (_QWORD *)(v22 + 8);
        v14 = v22 + v38 + 4;
        if ( v14 > v9 )
          goto LABEL_67;
LABEL_53:
        *v52 = *v49;
        if ( v51 >= 0x11 )
        {
          v53 = v38 + v22 + 4;
          if ( v53 <= v22 + 24 )
            v53 = v22 + 24;
          v54 = v53 - v22;
          v55 = (_QWORD *)(v22 + 16);
          v56 = v54 - 17;
          if ( v56 < 0x38 || v22 - (unsigned __int64)v49 + 8 < 0x20 )
          {
            v57 = v49;
            goto LABEL_59;
          }
          v60 = (_OWORD *)(v22 + 32);
          v61 = (v56 >> 3) + 1;
          v62 = v61 & 0x3FFFFFFFFFFFFFFCLL;
          v57 = &v49[v62];
          v55 = (_QWORD *)((char *)v55 + v62 * 8);
          v63 = (__int128 *)(v49 + 3);
          v64 = v61 & 0x3FFFFFFFFFFFFFFCLL;
          do
          {
            v65 = *(v63 - 1);
            v66 = *v63;
            v63 += 2;
            v64 -= 4;
            *(v60 - 1) = v65;
            *v60 = v66;
            v60 += 2;
          }
          while ( v64 );
          if ( v61 != (v61 & 0x3FFFFFFFFFFFFFFCLL) )
          {
LABEL_59:
            v58 = v57 + 1;
            do
            {
              v59 = *v58++;
              *v55++ = v59;
            }
            while ( (unsigned __int64)v55 < v14 );
          }
        }
      }
    }
    else
    {
      *(_QWORD *)v22 = *(_QWORD *)v41;
      *(_QWORD *)(v22 + 8) = *(_QWORD *)(v41 + 8);
      v14 = v38 + v22 + 4;
      *(_WORD *)(v22 + 16) = *(_WORD *)(v41 + 16);
    }
  }
  ++v13;
  v22 = v14 + v17;
  v23 = (unsigned __int16 *)&v13[v17];
  if ( v14 + v17 <= v9 && (unsigned __int64)v23 <= v10 )
  {
LABEL_22:
    v25 = v17 + v14;
    if ( v25 <= v14 + 8 )
      v25 = v14 + 8;
    v26 = v25 + ~v14;
    if ( v26 < 0x18 || v14 - (unsigned __int64)v13 < 0x20 )
    {
      v30 = v13;
      v31 = (_QWORD *)v14;
    }
    else
    {
      v27 = (v26 >> 3) + 1;
      v28 = 8 * (v27 & 0x3FFFFFFFFFFFFFFCLL);
      v29 = v27 & 0x3FFFFFFFFFFFFFFCLL;
      v30 = &v13[v28];
      v31 = (_QWORD *)(v14 + v28);
      v32 = (_OWORD *)(v14 + 16);
      v33 = (__int128 *)(v13 + 16);
      do
      {
        v34 = *(v33 - 1);
        v35 = *v33;
        v33 += 2;
        v29 -= 4;
        *(v32 - 1) = v34;
        *v32 = v35;
        v32 += 2;
      }
      while ( v29 );
      if ( v27 == (v27 & 0x3FFFFFFFFFFFFFFCLL) )
      {
LABEL_39:
        v44 = *v23;
        v42 = (unsigned __int8 *)(v23 + 1);
        v39 = v44;
        v38 = v15 & 0xF;
        v41 = v22 - v44;
        if ( v38 == 15 )
        {
LABEL_40:
          v45 = 0;
          if ( v11 >= (unsigned __int64)v42 )
            v46 = v11 - (_QWORD)v42;
          else
            v46 = 0;
          while ( 1 )
          {
            v13 = v42 + 1;
            if ( !v46 )
              return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
            v47 = *v42;
            --v46;
            ++v42;
            v45 += v47;
            if ( v47 != 255 )
            {
              v38 = v45 + 15;
              v48 = __CFADD__(v22, v45 + 15);
              if ( v45 == -1 || v48 )
                return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
              goto LABEL_50;
            }
          }
        }
        goto LABEL_36;
      }
    }
    do
    {
      v43 = *(_QWORD *)v30;
      v30 += 8;
      *v31++ = v43;
    }
    while ( (unsigned __int64)v31 < v22 );
    goto LABEL_39;
  }
LABEL_107:
  if ( v23 == v6 && v22 <= v7 )
  {
    sub_488(v14, (unsigned __int64)v13, v17);
    return (unsigned int)(v22 - a2);
  }
  return (unsigned int)(~(_DWORD)v13 + (_DWORD)a1);
}



/********************************************************************************/
Function: sub_2220
/********************************************************************************/

_QWORD *sub_2220()
{
  const char *v0; // x1
  unsigned __int64 v1; // x0
  int v2; // w9
  unsigned __int64 v3; // x0
  __int64 v4; // x8
  int v5; // w0
  unsigned __int8 *v6; // x0
  int v7; // w8
  int v8; // w9
  int v9; // t1
  _QWORD *result; // x0
  __int64 v11; // t1
  __int64 v12; // t1
  __int64 v13; // [xsp+0h] [xbp-1020h] BYREF
  unsigned __int8 v14[4096]; // [xsp+10h] [xbp-1010h] BYREF

  v0 = (const char *)sub_25B8(&unk_2F8, &v13, 16);
  do
    v1 = linux_eabi_syscall(__NR_openat, -100, v0, 0);
  while ( v1 == -4 );
  if ( v1 > 0xFFFFFFFFFFFFF000LL )
    v2 = -1;
  else
    v2 = v1;
  if ( v2 < 0 )
    return nullptr;
  do
    v3 = linux_eabi_syscall(__NR_read, v2, v14, 0xFFFu);
  while ( v3 == -4 );
  if ( v3 > 0xFFFFFFFFFFFFF000LL )
    v4 = -1;
  else
    v4 = v3;
  if ( v4 < 1 )
    return nullptr;
  v14[v4] = 0;
  v5 = linux_eabi_syscall(__NR_close, v2);
  v6 = sub_748(v14, 0x29u);
  v7 = 2;
  while ( v7 != 28 )
  {
    v9 = *v6++;
    v8 = v9;
    if ( v9 == 32 )
      ++v7;
    if ( !v8 )
      return nullptr;
  }
  result = (_QWORD *)sub_770(v6, nullptr, 0xAu);
  if ( result )
  {
    result = (_QWORD *)((char *)result + ((__int64)(*result << 32) >> 29) + 8);
    do
    {
      v11 = result[1];
      ++result;
    }
    while ( v11 );
    do
    {
      v12 = result[1];
      ++result;
    }
    while ( !v12 );
  }
  return result;
}



/********************************************************************************/
Function: sub_232C
/********************************************************************************/

__int64 __fastcall sub_232C(__int64 *a1, __int64 a2)
{
  __int64 v2; // x9
  __int64 *v3; // x8
  __int64 v4; // t1

  v2 = *a1;
  if ( !*a1 )
    return 0;
  v3 = a1 + 2;
  while ( v2 != a2 )
  {
    v4 = *v3;
    v3 += 2;
    v2 = v4;
    if ( !v4 )
      return 0;
  }
  return *(v3 - 1);
}



/********************************************************************************/
Function: sub_2358
/********************************************************************************/

char *__fastcall sub_2358(__int64 *a1)
{
  __int64 v2; // x19
  _DWORD *v3; // x0
  char *v4; // x8
  _DWORD *v5; // x8
  _DWORD *v6; // x9
  _DWORD *v7; // x10
  bool v9; // w11
  bool v10; // zf
  char **i; // x9

  v2 = sub_232C(a1, 5);
  v3 = (_DWORD *)sub_232C(a1, 3);
  v4 = nullptr;
  if ( !v3 || !v2 )
    return v4;
  v5 = nullptr;
  v6 = nullptr;
  v7 = nullptr;
  do
  {
    v9 = *v3 != 6 || v6 != nullptr;
    if ( v5 )
      v10 = 0;
    else
      v10 = *v3 == 2;
    if ( v10 )
    {
      v7 = v3;
      if ( v9 )
        goto LABEL_4;
    }
    else if ( v9 )
    {
      goto LABEL_4;
    }
    v6 = v3;
    v7 = v5;
LABEL_4:
    --v2;
    v3 += 14;
    v5 = v7;
  }
  while ( v2 );
  v4 = nullptr;
  if ( v6 )
  {
    if ( v7 )
    {
      v4 = (char *)v6 + *((_QWORD *)v7 + 2) - *((_QWORD *)v6 + 2);
      if ( v4 )
      {
        for ( i = (char **)(v4 + 8); ; i += 2 )
        {
          v4 = *(i - 1);
          if ( v4 == (_BYTE *)&dword_14 + 1 )
          {
            v4 = *i;
            if ( *i )
              return v4;
          }
          else if ( !v4 )
          {
            return v4;
          }
        }
      }
    }
  }
  return v4;
}



/********************************************************************************/
Function: sub_2434
/********************************************************************************/

__int64 __fastcall sub_2434(int *a1, unsigned __int64 a2)
{
  __int64 *v4; // x20
  char *v5; // x0
  __int64 v6; // x21
  __int128 v7; // kr10_16
  unsigned __int64 v8; // x12
  __int64 v9; // x11
  __int64 (__fastcall **v10)(__int64); // x21
  unsigned __int64 v11; // x20
  __int64 v12; // x24
  unsigned __int64 v13; // x23
  __int64 *v14; // x8
  __int64 v15; // t1
  __int64 *v16; // x10
  unsigned __int64 v17; // kr08_8
  __int64 v18; // x19
  __int64 v20; // x0
  __int64 v21; // x8
  __int64 (__fastcall *v22)(__int64); // x8
  __int128 v23; // [xsp+0h] [xbp-D0h] BYREF
  __int128 v24; // [xsp+10h] [xbp-C0h]
  __int128 v25; // [xsp+20h] [xbp-B0h]
  __int128 v26; // [xsp+30h] [xbp-A0h]
  __int128 v27; // [xsp+40h] [xbp-90h]
  __int128 v28; // [xsp+50h] [xbp-80h]
  __int128 v29; // [xsp+60h] [xbp-70h]
  __int128 v30; // [xsp+70h] [xbp-60h]
  __int128 v31; // [xsp+80h] [xbp-50h]

  v4 = sub_2220();
  v5 = sub_2358(v4);
  if ( !v5 )
    return 0;
  v6 = (__int64)v5;
  v24 = 0u;
  v25 = 0u;
  v26 = 0u;
  v27 = 0u;
  v28 = 0u;
  v29 = 0u;
  v30 = 0u;
  v31 = 0u;
  v23 = 0u;
  if ( (sub_1290(a1, a2, (__int64)v5, (unsigned __int64 *)&v23) & 1) == 0 )
    return 0;
  v7 = v24;
  if ( (sub_167C(*((__int64 **)&v24 + 1), v24, (__int64)v4, v6) & 1) == 0 )
  {
    sub_15BC((__int64)&v23);
    return 0;
  }
  v9 = **((_QWORD **)&v7 + 1);
  if ( **((_QWORD **)&v7 + 1) )
  {
    v10 = nullptr;
    v11 = 0;
    v12 = 0;
    v13 = 0;
    v14 = (__int64 *)(*((_QWORD *)&v7 + 1) + 16LL);
    do
    {
      v16 = v14 - 2;
      v17 = v8;
      v8 = *(v14 - 1);
      switch ( v9 )
      {
        case 25LL:
          v10 = (__int64 (__fastcall **)(__int64))(v8 + v7);
          break;
        case 26LL:
          v12 = v8 + v7;
          break;
        case 27LL:
          v11 = v8 >> 3;
          break;
        case 28LL:
          v13 = v8 >> 3;
          break;
        default:
          v8 = v17;
          break;
      }
      v15 = *v14;
      v14 += 2;
      v9 = v15;
      *v16 = 0;
      v16[1] = 0;
    }
    while ( v15 );
  }
  else
  {
    v13 = 0;
    v12 = 0;
    v11 = 0;
    v10 = nullptr;
  }
  v20 = sub_15E0((__int64)&v23);
  v18 = 0;
  if ( v12 && v13 )
  {
    v21 = v12 + 8 * v13;
    v18 = *(_QWORD *)(v21 - 8);
    *(_QWORD *)(v21 - 8) = 0;
  }
  for ( ; v11; ++v10 )
  {
    v22 = *v10;
    *v10 = nullptr;
    if ( (unsigned __int64)v22 + 1 >= 2 )
      v20 = v22(v20);
    --v11;
  }
  sub_1658((__int64)&v23);
  return v18;
}



/********************************************************************************/
Function: sub_25B8
/********************************************************************************/

_BYTE *__fastcall sub_25B8(_DWORD *a1, _BYTE *a2, __int64 a3)
{
  unsigned int v3; // w9
  unsigned int v4; // w14
  __int64 v5; // x8
  char *v6; // x10
  _BYTE *v7; // x12
  char v8; // t1
  __int64 v9; // x15
  int v10; // w0
  int v11; // w16
  unsigned int v12; // w17
  int v13; // w5
  unsigned int v14; // w4
  unsigned int v15; // w3
  int v16; // w5
  unsigned int v17; // w16
  unsigned int v19; // [xsp+8h] [xbp-8h]
  char v20; // [xsp+Ch] [xbp-4h]
  char v21; // [xsp+Dh] [xbp-3h]
  char v22; // [xsp+Eh] [xbp-2h]
  char v23; // [xsp+Fh] [xbp-1h]

  if ( a3 )
  {
    v3 = *a1;
    v4 = a1[1];
    v5 = 0;
    v6 = (char *)(a1 + 2);
    v7 = a2;
    do
    {
      v9 = v5 & 7;
      if ( (v5 & 7) == 0 )
      {
        v10 = -2;
        v11 = -3;
        do
        {
          v12 = v10 + 2;
          v11 += 4;
          v13 = (v3 << 6) ^ (v3 >> 8);
          v14 = v3 + v13;
          v15 = v4 + dword_2D7[(v10 + 2) & 6];
          v4 = v10 + 2 + v3 + v13 + v15;
          v16 = v15 + dword_2D7[((_BYTE)v10 + 3) & 7] + v13 + ((v4 << 6) ^ (v4 >> 8)) + 2 * v3;
          v10 = v12;
          v3 = v11 + v16;
        }
        while ( v12 < 0x3E );
        v3 = v16 + v11;
        v17 = v4 >> 8;
        v4 = v15 + v14 + v12;
        v19 = v3;
        v20 = v15 + v14 + v12;
        v21 = v17;
        v22 = BYTE2(v4);
        v23 = HIBYTE(v4);
      }
      ++v5;
      v8 = *v6++;
      *v7++ = *((_BYTE *)&v19 + v9) ^ v8;
    }
    while ( v5 != a3 );
  }
  return a2;
}

