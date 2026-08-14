// inferred from 4 accesses on `a1`
struct Struct_1_t {
    char _pad_start[280];
    __int64 field_118; // offset 280
    __int64 field_120; // offset 288
    __int64 field_128; // offset 296
    __int64 field_130; // offset 304
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

__int64 sub_1400F8CE0();
__int64 sub_140073FDC();
__int64 sub_140073CC9();
extern __int64 off_14012D270;

__int64 __fastcall sub_140073B30(struct Struct_1_t *a1) {
    __int64 rsp;
    struct Struct_3_t *ptr2;
    __int64 v6;
    __int64 v7;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 v10;
    __int64 v4;
    __int64 *src2;
    __int64 v12;
    struct Struct_4_t *ptr3;
    __int64 v9;
    __int64 v2;

    ptr2 = a1->field_118;
    v6 = ptr2->field_108;
    v7 = ptr2->field_100;
    ptr = (struct Struct_2_t *)v6;
    ptr -= v7;
    if (ptr > 0) {
        if (a1->field_130 != 1) {
            /* xadd %v7, 256(%(__int64)ptr2) */;
            if ((v7 - v6) < 0) {
                src = a1->field_120;
                ptr2 = a1->field_128;
                v10 = ptr2 - 1;
                v10 &= v7;
                v10 <<= 4;
                v4 = *(src + v10);
                src2 = *(src + v10 + 8);
                v12 = ptr2 + 3;
                if (ptr2 >= 0) v12 = ptr2;
                if (ptr2 >= 65) {
                    v12 >>= 2;
                    if (ptr <= v12) JUMPOUT(0x140074008);
                }
                if (v4 != 0) JUMPOUT(0x140073fdc);
            } else {
                ptr = a1->field_118;
                ptr->field_100 = v7;
            }
        } else {
            ptr = v6 - 1;
            ptr2->field_108 = ptr;
            *(__int64 *)rsp = *(__int64 *)rsp | 0;
            ptr3 = a1->field_118;
            v9 = ptr3->field_100;
            v7 = (__int64)ptr;
            v7 -= v9;
            if ((v7 < 0)) {
                ptr3->field_108 = v6;
            } else {
                src2 = a1->field_120;
                ptr2 = a1->field_128;
                v2 = ptr2 - 1;
                v2 &= (__int64)ptr;
                v2 <<= 4;
                v4 = *(src2 + v2);
                src2 = *(src2 + v2 + 8);
                if (ptr != v9) {
                    ptr = ptr2 + 3;
                    if (ptr2 >= 0) ptr = ptr2;
                    if (ptr2 < 65) JUMPOUT(0x140073fdc);
                    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr >> 2);
                    if (v7 >= ptr) JUMPOUT(0x140073fdc);
                    ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 >> 1);
                    a1 += 280;
                    sub_1400F8CE0(a1, ptr2, v6, 1);
                    return sub_140073FDC();
                } else {
                    /* cmpxchg %v6, 256(%(__int64)ptr3) */;
                    ptr = a1->field_118;
                    ptr->field_108 = v6;
                    if (!((0 /* unresolved: flags != */))) {
                        return sub_140073FDC();
                    }
                }
            }
        }
    }
    ptr = off_14012D270;
    ptr2 = __readgsqword(88);
    ptr = ((__int64 *)ptr2)[(__int64)ptr];
    v2 = ptr + 8;
    return sub_140073CC9();
}