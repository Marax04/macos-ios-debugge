// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();

__int64 __fastcall sub_1400FAE80(struct Struct_1_t *a1) {
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    char *str;
    __int64 *dst;
    __int64 v3;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    struct Struct_2_t *ptr;
    __int64 v9;
    __int64 v2;
    __int64 result;
    __int64 v8;

    dst = (__int64 *)a1;
    v3 = a1->field_0;
    v7 = v3 + v3;
    v5 = 4;
    if (v7 >= 5) v5 = v7;
    v6 = a1->field_8;
    v_28 = 8;
    v_20 = 8;
    sub_1400F2C50(str, v3, v6, v5);
    if (str == 1) {
        ptr = (struct Struct_2_t *)v_38;
        v3 = v_40;
        sub_1400F3326(ptr, v3);
        dst = (__int64 *)ptr;
        v3 = ptr->field_0;
        v9 = v3 + v3;
        v5 = 4;
        if (v9 >= 5) v5 = v9;
        v2 = ptr->field_8;
        v_28 = 16;
        v_20 = 8;
        sub_1400F2C50(str, v3, v2, v5);
        if (str == 1) JUMPOUT(0x1400faf4a);
        result = v_38;
        *(dst + 8) = result;
        *dst = v5;
        return result;
    } else {
        v8 = v_38;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}