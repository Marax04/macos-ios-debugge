__int64 sub_140046190();
__int64 sub_140053180();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140063E00(__int64 a1, __int64 a2) {
    int v_20;
    int v_28;
    int v_30;
    __int64 *src;
    __int64 i;
    __int64 v7;
    __int64 v9;
    __int64 v3;
    __int64 *v2;
    __int64 result;
    __int64 v8;

    v_30 = a2;
    if (a2 != 0) {
        src = (__int64 *)a1;
        i = 0;
        v7 = off_140108030;
        v9 = off_140108038;
        v3 = 0x8000000000000003;
        v_28 = a1;
        do {
            v2 = i * 344;
            result = *(__int64 *)((__int64)src + (__int64)v2 + 8);
            v_20 = result;
            v8 = *(__int64 *)((__int64)src + (__int64)v2 + 16);
            src = (__int64 *)v_28;
            v2 = (__int64 *)((__int64)v2 + (__int64)src);
            if (*v2 == 0) {
                ++i;
                a1 = v2 + 24;
                sub_140046190(a1);
                v2 += 168;
                sub_140053180(v2);
                return (__int64)v2;
            }
            ((__int64 (*)())v7)();
            ((__int64 (*)())v9)(result, 0, v_20);
            return (__int64)v2;
        } while (i != v_30);
    }
    return result;
}