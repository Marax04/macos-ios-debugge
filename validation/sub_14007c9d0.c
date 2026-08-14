__int64 sub_140082770();
extern __int64 off_140122B08;

__int64 __fastcall sub_14007C9D0(int *a1, __int64 *a2, __int64 a3, __int64 a4) {
    __int64 rsp;
    int arg_2;
    int arg_3;
    int arg_5;
    int v_138;
    int v_140;
    int v_148;
    int v_150;
    __int64 v_152;
    int v_153;
    int v_157;
    int v_15e;
    int v_190;
    int v_a0;
    int v_f0;
    char *dst;
    __int64 v5;
    __int64 v8;
    __int64 v4;
    __int64 *dst2;
    __int64 result;
    __int64 v2;
    int v9;
    int v10;
    __int64 v7;

    if (a3 != 0) {
        v_138 = (int)a2;
        v_140 = a3;
        v_148 = 0;
        v5 = 6;
        v8 = 0;
        v4 = &off_140122B08;
        dst2 = rsp + 160;
        result = 0;
        do {
            v2 = *(a2 + result);
            v9 = v2;
            if (v9 == 240) {
                v8 |= 128;
                ++result;
                v4 = 2;
                result = a3;
                v5 = 2;
                *dst2 = v4;
                *dst = v5;
                dst2 = (__int64 *)dst;
                v10 = v_a0;
                if (dst2 != 2) {
                    v5 = v_f0;
                    v_150 = v8;
                    v_152 = (__int64)dst2;
                    v_153 = v10;
                    v_157 = v5;
                    v_15e = v_190;
                    if (result >= a3) {
                        arg_5 = 0;
                        arg_2 = 514;
                    } else {
                        v2 = *(a2 + result);
                        v5 = v2;
                        v2 = result + 1;
                        v_148 = v2;
                        v4 = v5 - 196;
                        if (v4 < 2) JUMPOUT(0x14007cbee);
                        if (v5 == 15) JUMPOUT(0x14007cccb);
                        if (v5 != 98) JUMPOUT(0x14007ce1a);
                        if ((v8 & 1) != 0) JUMPOUT(0x14007debc);
                        v4 = (__int64)a2;
                        v7 = a3;
                        v8 = a4;
                        dst2 = (__int64 *)a1;
                        a1 = rsp + 312;
                        sub_140082770(a1);
                        a1 = 0xFFFFFFFFFFFFFF;
                        a1 = (int *)((__int64)(__int64)a1 & result);
                        result = (__int64)a1;
                        result >>= 8;
                        if (((__int64)a1 & 1) == 0) JUMPOUT(0x14007cf5f);
                        arg_3 = result;
                        result >>= 16;
                        arg_5 = result;
                        arg_2 = 2;
                    }
                } else {
                    arg_3 = v10;
                    arg_2 = 2;
                }
                return arg_2;
            }
            if (v9 == 242) {
                v8 |= 512;
                return v8;
            }
            if (v9 != 243) JUMPOUT(0x14007cc65);
            v8 |= 256;
            return v8;
        } while (a3 != result);
        return v8;
    }
    return result;
}