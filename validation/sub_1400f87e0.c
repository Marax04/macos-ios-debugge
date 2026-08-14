// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F8850();
__int64 sub_1400F3326();
__int64 sub_1400F88F1();

__int64 __fastcall sub_1400F87E0(struct Struct_1_t *a1) {
    int v_20;
    int v_38;
    int v_40;
    int v_70;
    char *str;
    __int64 *dst;
    __int64 v3;
    __int64 v2;
    __int64 v5;
    __int64 v6;
    __int64 v9;
    __int64 result;
    __int64 v11;
    __int64 v10;
    __int64 v8;
    __int64 v7;

    dst = (__int64 *)a1;
    v3 = a1->field_0;
    v2 = v3 + v3;
    v5 = 4;
    if (v2 >= 5) v5 = v2;
    v6 = a1->field_8;
    v_20 = 48;
    sub_1400F8850(str, v3, v6, v5);
    if (str == 1) {
        v9 = v_38;
        v3 = v_40;
        sub_1400F3326(v9, v3);
        dst = (__int64 *)v9;
        result = v_70;
        result += 7;
        result &= 248;
        v2 *= v7; /* unsigned; high half in v3 */;
        v11 = v2;
        result = (0 /* overflow check on (result & 248) */) ? 1 : 0;
        v10 = 0x7FFFFFFFFFFFFFF8;
        a1 = (v11 > v10) ? 1 : 0;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 | result);
        v11 = 1;
        if ((a1 == 0)) JUMPOUT(0x1400f8897);
        result = 8;
        v5 = 0;
        return sub_1400F88F1();
    } else {
        v8 = v_38;
        *(dst + 8) = v8;
        *dst = v5;
        return result;
    }
}