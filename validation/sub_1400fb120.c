// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_1400FB201();

__int64 __fastcall sub_1400FB120(struct Struct_1_t *a1) {
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    char *str;
    __int64 *dst;
    __int64 v9;
    __int64 v2;
    __int64 v4;
    __int64 v5;
    __int64 v8;
    __int64 v10;
    __int64 v11;
    __int64 result;
    __int64 v7;
    __int64 v6;

    dst = (__int64 *)a1;
    v9 = a1->field_0;
    v2 = v9 + v9;
    v4 = 4;
    if (v2 >= 5) v4 = v2;
    v5 = a1->field_8;
    v_28 = 56;
    v_20 = 4;
    sub_1400F2C50(str, v9, v5, v4);
    if (str == 1) {
        v8 = v_38;
        v10 = v_40;
        sub_1400F3326(v8, v10);
        v11 = v8;
        v10 = 1;
        if (v6 >= 0) JUMPOUT(0x1400fb1b0);
        result = 8;
        v4 = 0;
        return sub_1400FB201();
    } else {
        v7 = v_38;
        *(dst + 8) = v7;
        *dst = v4;
        return result;
    }
}