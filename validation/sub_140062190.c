// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F5F90();
__int64 sub_1400F27F0();

__int64 __fastcall sub_140062190(__int64 *a1, __int64 a2, __int64 a3) {
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v1;
    __int64 v6;
    __int64 v5;

    v2 = a3;
    ptr = (struct Struct_1_t *)a1;
    v2 -= a2;
    v4 = *a1;
    v1 = a1[2];
    v4 -= v1;
    if (v2 > v4) {
        v6 = a2;
        sub_1400F5F90(ptr, v1, v2);
        a2 = v6;
        v1 = ptr->field_10;
    }
    v5 = ptr->field_8;
    v5 += v1;
    sub_1400F27F0(v5, a2, v2);
    v1 += v2;
    ptr->field_10 = v1;
    return v1;
}