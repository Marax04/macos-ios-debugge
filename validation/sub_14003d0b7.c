__int64 sub_140040080();
__int64 sub_14003B328();

void __fastcall sub_14003D0B7(__int64 a1, __int64 a2, __int64 *a3) {
    int arg_468;
    int arg_500;
    int arg_508;
    int arg_558;
    int v_73;
    __int64 v6;
    __int64 v5;
    __int64 v3;
    __int64 v8;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    int v1;
    __int64 *dst;

    v_73 += a1;
    if ((0 /* overflow check on (v_73 + a1) */)) JUMPOUT(0x14003d0c8);
    a3[1] = 92;
    v6 = v2 - 6;
    arg_468 = a3;
    sub_140040080(a1, v6);
    v5 = arg_468;
    if (v1 == 0) {
        *dst = 67;
        v3 = v5;
    }
    v8 = arg_508;
    v4 = arg_558;
    v7 = arg_500;
    sub_14003B328();
}