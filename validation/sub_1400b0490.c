// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
};

__int64 sub_1400F3869();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400B0664();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011A950;

__int64 __fastcall sub_1400B0490(int *a1, __int64 *a2, int a3, int *a4) {
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    char *str;
    __int64 v10;
    __int64 *dst;
    __int64 v3;
    struct Struct_1_t *result;
    __int64 v7;
    struct Struct_2_t *ptr;
    int v11;
    __int64 v9;
    __int64 *i;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v6;

    v10 = a1[2];
    if (v10 != 0) {
        dst = (__int64 *)a4;
        v3 = a3;
        v_30 = (int)a1;
        result = *(a1 + 8);
        v7 = *a4;
        ptr = result + 40;
        a1 = (int *)v7;
        v11 = 0;
        while (a1 < v3) {
            a3 = *(__int64 *)((__int64)a2 + (__int64)a1);
            ++a1;
            *dst = a1;
            if (a3 != 1) {
                ptr += 40;
                v10 -= (__int64)a4;
                result = (struct Struct_1_t *)v_30;
                result->field_10 = v10;
                return (__int64)result;
            }
            a1 =  + (__int64)(__int64)str*4;
            a1 = (int *)((__int64)a1 + (__int64)str);
            v9 = str + 1;
            if (((__int64 *)result)[(__int64)a1] != 0) {
                result += (__int64)(__int64)a1*8;
                i = result->field_8;
                v_28 = (int)a2;
                off_140108030(a1, a2, a3, 0);
                off_140108038(result, 0, i);
                a2 = (__int64 *)v_28;
            }
            a4 = 1;
            if (v9 != v10) {
                i = v7 + a2;
                ++i;
                v5 = v10 - 1;
                v_40 = v3;
                v_38 = v10;
                a1 = v7 + str;
                ++a1;
                while (a1 < v3) {
                    result = *(__int64 *)((__int64)i + (__int64)str);
                    a1 = v7 + str;
                    a1 += 2;
                    *dst = a1;
                    if (result != 1) {
                        result =  + (__int64)(__int64)a4*8;
                        result += (__int64)(__int64)result*4;
                        a1 = (int *)ptr;
                        a1 = (int *)((__int64)a1 - (__int64)result);
                        a2 = ptr->field_20;
                        result = (struct Struct_1_t *)(-(__int64)result);
                        *(__int64 *)((__int64)ptr + (__int64)result + 32) = a2;
                        xmm0 = _mm_loadu_si128((__m128i *)ptr);
                        xmm1 = _mm_loadu_si128((__m128i *)(ptr + 16));
                        _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                        _mm_storeu_si128((__m128i *)a1, xmm0);
                        ptr += 40;
                        return (__int64)ptr;
                    }
                    ++a4;
                    if (ptr->field_0 == 0) {
                        return (__int64)a4;
                    }
                    v9 = ptr->field_8;
                    v10 = v7;
                    v6 = (__int64)a4;
                    v3 = v5;
                    off_140108030(a1, a2, a3, a4);
                    off_140108038(result, 0, v9);
                    v5 = v3;
                    v7 = v10;
                    v10 = v_38;
                    v3 = v_40;
                    return v3;
                }
                a3 = &off_14011A950;
                sub_1400F3869(a1, v3, a3, v7);
                if (v3 < 0) {
                    sub_1400F3360();
                }
                if ((0 /* unresolved: flags == */)) JUMPOUT(0x1400b065f);
                i = (__int64 *)a1;
                v3 = (__int64)a2;
                sub_14002EDF0(8);
                if (result == 0) JUMPOUT(0x1400b0676);
                a2 = (__int64 *)v3;
                a1 = (int *)i;
                return sub_1400B0664();
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}