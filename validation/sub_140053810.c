__int64 sub_140046190();

__int64 __fastcall sub_140053810(int *a1, __int64 a2) {
    int v_20;
    __int64 v5;
    __int64 *src;
    __int64 i;
    __int64 v6;
    __int64 v2;
    __int64 result;

    v5 = a1[2];
    if (v5 != 0) {
        src = *(a1 + 8);
        i = 0;
        v6 = 1;
        v_20 = v5;
        do {
            v2 = i * 328;
            a1 = src + v2;
            a1 += 176;
            sub_140046190(a1);
            a1 = *(src + v2);
            result = a1 - 8;
            if (a1 < 8) result = v6;
            ++i;
        } while (i != v5);
    }
    return result;
}