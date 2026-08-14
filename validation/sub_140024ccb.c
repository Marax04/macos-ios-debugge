__int64 sub_1400233F1();
__int64 sub_140024D20();

__int64 __fastcall sub_140024CCB(size_t a1, __int64 *a2) {
    int v_8;
    int v_f;
    char *str;
    __int64 *src;
    __int64 *dst;
    __int64 v6;
    __int64 *v2;
    __int64 v5;
    int v1;

    src = a2;
    dst = (__int64 *)a1;
    v6 = a2[2];
    v2 = str - 16;
    sub_1400233F1();
    if (*v2 != 1) {
        --v6;
        v5 = v_8;
        if (v5 >= v6) JUMPOUT(0x140024d1c);
        a1 = *(src + 24);
        ++a1;
        if (a1 <= 500) JUMPOUT(0x140024d32);
        *(dst + 8) = 1;
        return sub_140024D20();
    } else {
        v1 = v_f;
        *(dst + 8) = v1;
        return sub_140024D20();
    }
}