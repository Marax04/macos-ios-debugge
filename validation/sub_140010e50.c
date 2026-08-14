// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_1400F37D0();
__int64 sub_1400F27F0();
extern __int64 off_140114978;
extern __int64 off_14010AED0;
extern __int64 off_140115F00;

__int64 __fastcall sub_140010E50(__int64 *a1, int a2, int a3) {
    __int64 *v5;
    __int64 result;
    __int64 v7;
    struct Struct_3_t *ptr3;
    __int64 *src;
    __int64 v3;
    struct Struct_2_t *ptr2;
    __int64 v2;
    __int64 v9;
    struct Struct_1_t *ptr;

    v5 = a1[2];
    if (ptr <= v5) {
        a3 = (ptr != 0) ? 1 : 0;
        result = (ptr < v5) ? 1 : 0;
        if ((a3 & result) != 0) {
            v5 = *(a1 + 8);
            if (*(__int64 *)((__int64)v5 + (__int64)ptr) <= 191) {
                v7 = &off_140114978;
                a3 = &off_14010AED0;
                sub_1400F37D0(v7, 48, a3);
                ptr3 = ptr->field_0;
                src = ptr->field_8;
                src = *(src + 24);
                a2 = &off_140115F00;
                a3 = 5;
                JUMPOUT(src);
                v3 = a3;
                ptr2 = (struct Struct_2_t *)ptr3;
                result = ptr3->field_0;
                v2 = ptr3->field_10;
                result -= v2;
                if (a3 > result) JUMPOUT(0x140010f00);
                v9 = ptr2->field_8;
                v9 += v2;
                sub_1400F27F0(v9, a2, v3);
                v2 += v3;
                ptr2->field_10 = v2;
                result = 0;
                return result;
            }
        }
        a1[2] = ptr;
    }
    return result;
}