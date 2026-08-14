// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char field_18; // offset 24
    int field_19; // offset 25
    __int16 field_1D; // offset 29
    __int64 field_1F; // offset 31
};

__int64 sub_140045964();
__int64 sub_1400459E1();

__int64 __fastcall sub_1400458C0(__int64 *a1, int *a2) {
    char *dst;
    struct Struct_1_t *ptr;
    __int64 v1;
    __int64 v3;
    __int64 v9;
    __int64 v4;
    __int64 v10;
    __int64 v6;
    __int64 v7;
    __int64 v2;
    __int64 v8;

    *dst = -2;
    ptr = *(a2 + 8);
    if (ptr != a2[3]) {
        v1 = ptr + 32;
        *(a2 + 8) = v1;
        v3 = ptr->field_0;
        v9 = v3;
        v9 = -v9;
        if ((0 /* overflow check on (-v9) */)) {
            v4 = ptr->field_8;
            v10 = ptr->field_10;
            if ((ptr->field_18 & 1) != 0) JUMPOUT(0x1400459d6);
            if (v10 == 0) JUMPOUT(0x1400459d6);
            v6 = ptr->field_1D;
            v7 = ptr->field_1F;
            v7 <<= 16;
            v7 |= v6;
            v7 <<= 32;
            ptr = ptr->field_19;
            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | v7);
            v6 = v4 + v10;
            v2 = v4 + 1;
            return sub_140045964();
        }
    }
    v8 = 0x8000000000000000;
    *a1 = v8;
    return sub_1400459E1();
}