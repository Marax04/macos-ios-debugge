// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3340();
__int64 sub_1400F37D0();
__int64 sub_14007BFD8();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;

__int64 __fastcall sub_14007BDE0(int *a1, int *a2) {
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v9;
    __int64 *dst2;
    __int64 v13;
    __int64 *result;
    __int64 v5;
    __int64 v12;
    __int64 v10;
    __int64 v6;
    __int64 *dst3;
    __int64 v8;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    dst = *a2;
    v9 = *(dst + 98);
    sub_14002EDF0(0, 200);
    if (result != 0) {
        dst2 = result;
        *result = 0;
        v13 = ptr->field_10;
        result = *(dst + 98);
        v5 = v13;
        v5 = ~v5;
        v5 += (__int64)result;
        *(dst2 + 98) = v5;
        if (v5 < 12) {
            v12 = *(dst + v13*8 + 8);
            a1 = dst2 + 8;
            a2 = dst + v13*8;
            a2 += 16;
            v5 <<= 3;
            sub_1400F27F0(a1, a2, v5);
            *(dst + 98) = v13;
            v10 = *(dst2 + 98);
            v5 = v10 + 1;
            if (v10 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, v5, 12, v6);
                sub_1400F3340(8, 200);
                v6 = &off_14011D898;
                sub_1400F3600(0, v5, 11, v6);
            } else {
                v9 -= v13;
                if (v9 == v5) {
                    a1 = (int *)dst2;
                    a1 += 104;
                    a2 = dst + v13*8;
                    a2 += 112;
                    v5 <<= 3;
                    sub_1400F27F0(a1, a2, v5);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    dst3 = *(dst2 + (__int64)(__int64)a2*8 + 104);
                    *dst3 = dst2;
                    *(dst3 + 96) = a2;
                    while (a2 < v10) {
                    }
                    *(__int64 *)ptr2 = (__int64)(dst);
                    ptr2->field_8 = result;
                    ptr2->field_20 = v12;
                    ptr2->field_10 = dst2;
                    ptr2->field_18 = result;
                    return (__int64)dst3;
                }
            }
            a1 = &off_14011D858;
            v8 = &off_14011D880;
            sub_1400F37D0(a1, 40, v8);
            ptr2 = (struct Struct_2_t *)a1;
            if (v8 == 0) JUMPOUT(0x14007bf75);
            if (v8 >= 15) JUMPOUT(0x14007bf8f);
            result = (__int64 *)v5;
            result = (__int64 *)((__int64)(__int64)result & 8);
            result += 8;
            v12 = 4;
            if (v8 >= 4) v12 = result;
            return sub_14007BFD8();
        }
        return v12;
    }
    return (__int64)result;
}