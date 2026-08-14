// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();

__int64 __fastcall sub_1400F6010(struct Struct_1_t *a1) {
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    char *str;
    __int64 *dst;
    __int64 v11;
    __int64 v8;
    __int64 v5;
    __int64 v6;
    struct Struct_2_t *ptr;
    __int64 result;
    __int64 i;
    __int64 *src;
    __int64 i2;
    __int64 v9;

    dst = (__int64 *)a1;
    v11 = a1->field_0;
    v8 = v11 + v11;
    v5 = 4;
    if (v8 >= 5) v5 = v8;
    v6 = a1->field_8;
    v_28 = 32;
    v_20 = 8;
    sub_1400F2C50(str, v11, v6, v5);
    if (str == 1) {
        ptr = (struct Struct_2_t *)v_38;
        sub_1400F3326(ptr, v_40);
        result = ptr->field_8;
        i = ptr->field_10;
        if (i < result) {
            src = ptr->field_0;
            result = -result;
            ++i;
            i2 = *(src + i - 1);
            while (i2 != 34) {
                if (i2 != 92) {
                    if (i2 >= 32) {
                        ptr->field_10 = i;
                        i2 = result + i;
                        ++i2;
                        ++i;
                    }
                }
            }
        }
        return i;
    } else {
        v9 = v_38;
        *(dst + 8) = v9;
        *dst = v5;
        return result;
    }
}