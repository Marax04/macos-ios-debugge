// inferred from 2 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27FC();
__int64 sub_1400276B6();
__int64 sub_1400276AC();

__int64 __fastcall sub_1400275E0(int a1, __int64 a2,struct Struct_1_t *a3) {
    int v_20;
    __int64 *src;
    __int64 v8;
    __int64 v2;
    __int64 v10;
    struct Struct_2_t *ptr;
    __int64 v11;
    __int64 i;
    __int64 v3;
    __int64 v5;
    __int64 v4;
    __int64 result;

    if (a3->field_0 == 5) {
        src = a3->field_8;
        if (src != 0) {
            v8 = a2;
            v2 = a1;
            v10 = ((__int64 *)a3)[2];
            do {
                ptr = src + 360;
                a1 = *(src + 626);
                v_20 = a1;
                a1 =  + a1*8;
                v11 = a1 + a1*2;
                i = -1;
                while (v11 != 0) {
                    v3 = ptr + 24;
                    a2 = ptr->field_8;
                    v5 = ptr->field_10;
                    v4 = v8;
                    v4 -= v5;
                    if (v4 < 0) v5 = v8;
                    sub_1400F27FC(v2, a2, v5);
                    if (result != 0) v4 = ptr;
                    result = (v4 < 0) ? 1 : 0;
                    a1 = (v4 > 0) ? 1 : 0;
                    a1 -= result;
                    v11 -= 24;
                    ++i;
                    ptr = (struct Struct_2_t *)v3;
                    result = a1;
                    if (a1 != 0) {
                        --v10;
                        if (!((v10 < 0))) {
                            src = *(src + i*8 + 632);
                        }
                        result = 0;
                        return sub_1400276B6();
                    }
                    return sub_1400276AC();
                }
                i = v_20;
                return i;
            } while (true);
        }
    }
    return result;
}