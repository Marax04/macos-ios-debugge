__int64 sub_140028770();
__int64 sub_14003407D();
__int64 sub_1400340C6();
extern __int64 off_140121B6C;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140033EF0(int *a1) {
    int v_10;
    int v_8;
    char *dst;
    __int64 v4;
    __int64 result;
    __int64 v2;
    __int64 v9;
    __int64 *src;
    __int64 v7;
    __int64 v8;
    __int64 *dst2;
    __int64 v5;
    __int64 v3;

    *dst = -2;
    v_10 = (int)a1;
    v4 = a1 + 25;
    result = 0;
    v2 = 0xFFFFFFFF00000003;
    v9 = 0x600000002;
    src = &off_140121B6C;
    v7 = off_140108030;
    v8 = off_140108038;
    do {
        v_8 = result;
        a1 = (int *)v_10;
        dst2 = a1[2];
        v5 = (__int64)dst2;
        v5 -= result;
        while (!((v5 <= 0))) {
            a1[3] = 1;
            v3 = *(a1 + 8);
            v3 += result;
            sub_140028770(0xFFFFFFF5, v3, v5);
            a1 = (int *)v3;
            a1 = (int *)((__int64)(__int64)a1 & v2);
            if (a1 != v9) v5 = v3;
            if ((result & 1) != 0) v3 = v5;
            dst2 = (__int64 *)v_10;
            *(dst2 + 24) = 0;
            if (a1 == v9) {
                if (v3 == 0) JUMPOUT(0x140034072);
                result = v_8;
                result += v3;
            }
            if ((result & 1) == 0) {
                return result;
            }
            result = v5;
            result &= 3;
            result = *(src + result*4);
            result += (__int64)src;
            JUMPOUT(result);
            result = v_8;
            return sub_14003407D();
        }
        if (result == 0) JUMPOUT(0x14003406e);
        v4 = 0;
        v5 = 0;
        v2 = v_10;
        if (dst2 >= result) JUMPOUT(0x1400340ae);
        return sub_1400340C6();
    } while (true);
}