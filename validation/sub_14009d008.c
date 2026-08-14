__int64 sub_14009CFF0();

__int64 __fastcall sub_14009D008(size_t *a1, __int64 a2, int a3) {
    __int64 v4;
    __int64 v5;
    __int64 v6;
    __int64 v3;
    __int64 v2;
    __int64 v1;

    *a1 = a1;
    *(a1 + v1*4) = a3;
    a3 = 0;
    v4 = v1;
    if (a2 < v1) v1 = a2;
    v5 =  + a3*2 + 1;
    if (v5 >= v1) JUMPOUT(0x14009cff0);
    v6 = a3 + a3;
    do {
        v3 = v6 + 2;
        v2 = v5;
        v5 = *(a1 + a3*4);
        v6 = *(a1 + v2*4);
        if (v5 >= v6) JUMPOUT(0x14009cff0);
        *(a1 + a3*4) = v6;
        *(a1 + v2*4) = v5;
        v6 = v2 + v2;
        v5 =  + v2*2 + 1;
        a3 = v2;
    } while (v5 < v4);
    return sub_14009CFF0();
}