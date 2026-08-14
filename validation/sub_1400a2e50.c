// inferred from 4 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[36];
    __int64 field_34; // offset 52
    __int64 field_3C; // offset 60
    char _pad_3C[118];
    __int64 field_BA; // offset 186
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002EDF0();

__int64 __fastcall sub_1400A2E50(int *a1, int *a2, int *a3, __int64 *a4) {
    struct Struct_3_t *ptr2;
    int v9;
    struct Struct_2_t *ptr;
    __int64 *dst;
    __int64 *dst2;
    __int64 v2;
    __int64 v8;
    __int64 i;
    struct Struct_1_t *result;

    ptr2 = (struct Struct_3_t *)a4;
    v9 = (int)a3;
    ptr = (struct Struct_2_t *)a2;
    dst = (__int64 *)a1;
    dst2 = *a2;
    if (dst2 == 0) {
        sub_14002EDF0(0, 192, a3);
        if (result == 0) JUMPOUT(0x1400a3968);
        *(__int64 *)result = (__int64)(0);
        *(__int64 *)ptr = (__int64)(result);
        ptr->field_8 = 0;
        result->field_BA = 1;
        result->field_8 = v9;
        a1 = ptr2->field_0;
        result->field_34 = a1;
        a1 = ptr2->field_8;
        result->field_3C = a1;
        ptr->field_10 = ptr->field_10 + 1;
        *dst = 3;
    } else {
        v2 = ptr->field_8;
        do {
            a1 = dst2 + 8;
            v8 = *(dst2 + 186);
            a2 =  + v8*4;
            i = -1;
            while (a2 != 0) {
                a3 = (v9 > *(a1 + i*4 + 4)) ? 1 : 0;
                a3 -= 0;
                ++i;
                a2 -= 4;
                a2 = a3;
                if (a3 != 0) {
                    --v2;
                    if ((v2 < 0)) JUMPOUT(0x1400a2f6d);
                    dst2 = *(dst2 + i*8 + 192);
                }
                result = i + i*2;
                a1 = *(dst2 + (__int64)(__int64)result*4 + 60);
                *(dst + 8) = a1;
                a1 = *(dst2 + (__int64)(__int64)result*4 + 52);
                *dst = a1;
                a1 = ptr2->field_0;
                *(dst2 + (__int64)(__int64)result*4 + 52) = a1;
                a1 = ptr2->field_8;
                *(dst2 + (__int64)(__int64)result*4 + 60) = a1;
                return (__int64)a1;
            }
            i = v8;
            return i;
        } while (true);
    }
    return (__int64)result;
}