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

__int64 sub_1400F6940();
__int64 sub_1400F3326();

__int64 __fastcall sub_1400F7130(struct Struct_1_t *a1) {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    char *str;
    __int64 *dst;
    __int64 v3;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    __int64 v10;
    struct Struct_2_t *ptr;
    __int64 v9;
    __int64 v2;
    __int64 v12;
    __int64 result;
    __int64 v8;

    dst = (__int64 *)a1;
    v3 = a1->field_0;
    v7 = v3 + v3;
    v5 = 4;
    if (v7 >= 5) v5 = v7;
    v6 = a1->field_8;
    v_28 = 32;
    v_20 = 8;
    v10 = str - 24;
    sub_1400F6940(v10, v3, v6, v5);
    if (v_18 == 1) {
        ptr = (struct Struct_2_t *)v_10;
        v3 = v_8;
        sub_1400F3326(ptr, v3);
        dst = (__int64 *)ptr;
        v3 = ptr->field_0;
        v9 = v3 + v3;
        v5 = 4;
        if (v9 >= 5) v5 = v9;
        v2 = ptr->field_8;
        v_28 = 40;
        v_20 = 8;
        v12 = str - 24;
        sub_1400F6940(v12, v3, v2, v5);
        if (v_18 == 1) JUMPOUT(0x1400f71fe);
        result = v_10;
        *(dst + 8) = result;
        *dst = v5;
        return result;
    } else {
        v8 = v_10;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}