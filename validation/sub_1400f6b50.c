extern __int64 off_140108260;
extern __int64 off_140108060;

int __fastcall sub_1400F6B50(int *a1) {
    int v_1;
    __int64 *src;
    int result;
    __int64 v2;
    __int64 v5;
    __int64 v3;

    src = (__int64 *)a1;
    result = *a1;
    if (result == 1) {
        a1 = 0xFFFFFF9D;
        result = *src;
        while (result == 1) {
            /* test a1 , a1 */;
            ++a1;
        }
    }
    if (result == 0) {
        a1 = 1;
        result = 0;
        /* cmpxchg %(__int64)a1, (%(__int64)src) */;
        if ((0 /* unresolved: flags != */)) {
            v2 = off_140108260;
            v5 = off_140108060;
            do {
                v_1 = 2;
                ((__int64 (*)())v2)(src, v3, 1, 0xFFFFFFFF);
                if (result == 1) {
                    result = *src;
                    a1 = 0xFFFFFF9D;
                    do {
                        result = *src;
                        v3 = a1 + 1;
                        a1 = (int *)v3;
                    } while ((a1 != 0));
                }
                ((__int64 (*)())v5)();
                return (int)a1;
            } while (result != 1);
        }
        return (int)a1;
    }
    return result;
}