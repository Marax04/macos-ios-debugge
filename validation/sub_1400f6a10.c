// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F6AB1();

__int64 __fastcall sub_1400F6A10(struct Struct_1_t *a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 v2;
    __int64 v3;
    __int64 result;

    if (a4 == 0) {
        v2 = a1->field_0;
        a4 = a1->field_10;
        a2 += v2;
        ++a2;
        v3 = a1->field_18;
        if (v3 >= 4) JUMPOUT(0x1400f6a5a);
        return sub_1400F6AB1();
    } else {
        result = 0;
        return result;
    }
}