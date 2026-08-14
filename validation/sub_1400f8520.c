// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();

__int64 __fastcall sub_1400F8520(struct Struct_1_t *a1) {
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    char *str;
    __int64 *dst;
    __int64 v9;
    __int64 result;
    __int64 v5;
    __int64 v6;
    __int64 v2;
    int v7;

    dst = (__int64 *)a1;
    v9 = a1->field_0;
    result = v9 + v9;
    v5 = 4;
    if (result >= 5) v5 = result;
    v6 = a1->field_8;
    v_28 = 144;
    v_20 = 8;
    sub_1400F2C50(str, v9, v6);
    if (str == 1) {
        sub_1400F3326(v_38, v_40);
        if (v7 == 0) JUMPOUT(0x1400f859e);
        result = 0;
        return result;
    } else {
        v2 = v_38;
        *(dst + 8) = v2;
        *dst = v5;
        return result;
    }
}