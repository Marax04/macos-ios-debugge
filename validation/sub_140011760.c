// inferred from 5 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_140011935();
__int64 sub_14001195B();

__int64 __fastcall sub_140011760(int a1, int a2,struct Struct_1_t *a3) {
    __int64 arg_4;
    int arg_6;
    int arg_8;
    int v_10;
    int v_18;
    int v_8;
    char *dst;
    __int64 *result;
    __int64 *src;
    __int64 i;
    __int64 v10;
    __int64 *src2;
    __int64 v8;
    __int64 v4;
    __int64 *src3;
    __int64 *src4;
    __int64 *src5;

    result = 0xE0000020;
    *dst = result;
    v_10 = a1;
    v_8 = a2;
    src = a3->field_20;
    v_18 = (int)a3;
    if (src == 0) {
        i = a3->field_18;
        if (i == 0) JUMPOUT(0x140011929);
        src = a3->field_10;
        i <<= 4;
        v10 = src + i;
        src2 = a3->field_0;
        i -= 16;
        i >>= 4;
        ++i;
        v8 = 0;
        v4 = dst - 16;
        do {
            a3 = *(src2 + v8 + 8);
            src3 = src + v8;
            a1 = *src3;
            a2 = v4;
            ((__int64 (*)())(arg_8))();
            if (result == 0) {
                v8 += 16;
                src3 += 16;
                result = (__int64 *)v_18;
                if (i >= *(result + 8)) JUMPOUT(0x140011959);
                return sub_140011935();
            }
            result = 1;
            return sub_14001195B();
        } while (src3 != v10);
        return (__int64)result;
    } else {
        result = a3->field_28;
        if (result == 0) {
            i = 0;
            result = (__int64 *)v_18;
            if (i >= *(result + 8)) JUMPOUT(0x140011959);
            return sub_140011935();
        } else {
            result = (__int64 *)((__int64)(__int64)result << 4);
            v10 = result + (__int64)(__int64)result*2;
            src4 = a3->field_0;
            src5 = a3->field_10;
            src4 += 8;
            v4 = 0;
            src3 = dst - 16;
            i = 0;
            do {
                a3 = *src4;
                result = *(src + v4 + 16);
                if (result == 0) {
                    result = *(src + v4 + 18);
                    a1 = *(src + v4);
                    if (a1 != 2) {
                        if (a1 != 1) {
                            a1 = *(src + v4 + 2);
                            a2 = *(src + v4 + 40);
                            a3 = *(src + v4 + 32);
                            a3 = (struct Struct_1_t *)((__int64)(__int64)a3 << 4);
                            *dst = a2;
                            arg_4 = (__int64)result;
                            arg_6 = a1;
                            a1 = *(__int64 *)((__int64)src5 + (__int64)a3);
                            a2 = (int)src3;
                            ((__int64 (*)())(*(__int64 *)((__int64)src5 + (__int64)a3 + 8)))();
                            if (result == 0) {
                                src4 += 16;
                                v4 += 48;
                                ++i;
                                return i;
                            }
                            return i;
                        }
                        a1 = *(src + v4 + 8);
                        a1 <<= 4;
                        a1 = *(src5 + a1 + 8);
                        return a1;
                    }
                    a1 = 0;
                    return a1;
                }
                if (result != 1) {
                    result = 0;
                    a1 = *(src + v4);
                    if (a1 != 2) {
                        return a1;
                    }
                    return a1;
                }
                result = *(src + v4 + 24);
                result = (__int64 *)((__int64)(__int64)result << 4);
                result = *(__int64 *)((__int64)src5 + (__int64)result + 8);
                a1 = *(src + v4);
                if (a1 == 2) {
                    return a1;
                }
                return a1;
            } while (v10 != v4);
            return a1;
        }
    }
    return (__int64)result;
}