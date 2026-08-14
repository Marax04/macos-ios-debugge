// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3570();
__int64 sub_1400F27F0();

__int64 __fastcall sub_140010EC0(__int64 *a1, __int64 a2, __int64 a3) {
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    __int64 result;

    v3 = a3;
    ptr = (struct Struct_1_t *)a1;
    v5 = *a1;
    v2 = a1[2];
    v5 -= v2;
    if (a3 > v5) {
        v7 = a2;
        sub_1400F3570(ptr, v2, v3);
        v2 = ptr->field_10;
    }
    v6 = ptr->field_8;
    v6 += v2;
    sub_1400F27F0(v6, a2, v3);
    v2 += v3;
    ptr->field_10 = v2;
    result = 0;
    return result;
}