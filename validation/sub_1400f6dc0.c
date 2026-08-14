__int64 sub_1400F6EE6();
__int64 off_140108268();
extern __int64 off_140121B4C;
extern __int64 off_140108260;
extern __int64 off_140108060;

int __fastcall sub_1400F6DC0(__int64 *a1, int a2, size_t a3, int a4) {
    int v_34;
    int v_38;
    int v_8;
    char *dst;
    __int64 *v2;
    __int64 v3;
    int result;
    __int64 v7;
    __int64 v4;
    __int64 v5;
    __int64 v6;

    *dst = -2;
    v2 = (__int64 *)a4;
    v3 = a3;
    result = *a1;
    if (a2 == 0) {
        v7 = &off_140121B4C;
        v4 = off_140108260;
        v5 = off_140108060;
        return sub_1400F6EE6();
    } else {
        v6 = off_140108260;
        v7 = off_140108060;
        do {
            a4 = result;
            a4 &= 3;
            a2 = result;
            a2 &= 4;
            a3 = a4 - 2;
            a2 |= 1;
            /* cmpxchg %a2, (%(__int64)a1) */;
        } while ((a2 != 0));
        a3 = (a4 == 2) ? 1 : 0;
        v_8 = (int)a1;
        v_38 = 0;
        v_34 = a3;
        a2 = dst - 56;
        a1 = (__int64 *)v3;
        ((__int64 (*)())(*(v2 + 32)))();
        result = v_38;
        a1 = (__int64 *)v_8;
        result = _InterlockedExchange64(a1, result);
        if ((result & 4) != 0) {
            off_140108268(a1, a2, a3);
        }
        return result;
    }
}