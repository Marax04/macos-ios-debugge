// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    char _pad_100[120];
    __int64 field_180; // offset 384
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[2168];
    __int64 field_880; // offset 0x880
};

__int64 sub_1400F4184();
__int64 sub_14001B630();
__int64 sub_1400F4181();

__int64 __fastcall sub_1400F40B0(struct Struct_1_t *a1, int *a2) {
    __int64 rsp;
    __int64 *dst;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    __int64 v1;
    __int64 v8;
    struct Struct_2_t *ptr;
    __int64 v5;

    dst = (__int64 *)a1;
    v2 = a1->field_100;
    *(__int64 *)rsp = *(__int64 *)rsp | 0;
    v7 = a1 + 384;
    v6 = a1->field_180;
    v1 = *a2;
    v8 = v7;
    ptr = (struct Struct_2_t *)v6;
    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr & -8);
    while (!((ptr == 0))) {
        a1 = (struct Struct_1_t *)v6;
        v6 = ptr->field_0;
        a2 = (int *)v6;
        a2 = (int *)((__int64)(__int64)a2 & 7);
        while (a2 == 1) {
            v6 &= -8;
            v5 = (__int64)a1;
            /* cmpxchg %v6, (%v8) */;
            if ((v6 != 0)) {
                a1 = (struct Struct_1_t *)v5;
                if (((__int64)a1 & 7) != 0) JUMPOUT(0x1400f4181);
                ptr = (struct Struct_2_t *)a1;
                v2 += 2;
                *(dst + 256) = v2;
                return sub_1400F4184();
            }
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & -8);
            sub_14001B630(a1, v1);
            a1 = (struct Struct_1_t *)v6;
            if (((__int64)a1 & 7) == 0) {
                return (__int64)a1;
            }
            return sub_1400F4181();
        }
        a1 = ptr->field_880;
        a2 = (((__int64)a1 & 1) == 0) ? 1 : 0;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & -2);
        a1 = (a1 == v2) ? 1 : 0;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 | (__int64)a2);
        v8 = (__int64)ptr;
        return sub_1400F4184();
    }
    return v8;
}