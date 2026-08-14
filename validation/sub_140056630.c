// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
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

__int64 sub_1400F3B20();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_1400F3360();
extern __int64 off_140115F58;
extern __int64 off_140116000;

__int64 __fastcall sub_140056630(int *a1,struct Struct_1_t *a2, __int64 a3) {
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    struct Struct_2_t *ptr;
    __int64 v8;
    __int64 result;
    __int64 v10;
    struct Struct_3_t *ptr2;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 v11;
    __int64 v6;
    __int64 i;
    __m128i xmm0;

    ptr = (struct Struct_2_t *)a1;
    v8 = 0;
    result = (a3 != 0) ? 1 : 0;
    if (a3 != 0) {
        a3 <<= 4;
        v10 = a2 + a3;
        v8 = result;
        v8 <<= 4;
        ptr2 = a2 + v8;
        v4 = a3 - 16;
        v4 >>= 4;
        result = a3;
        a1 = (int *)a2;
        while (result != 0) {
            result -= 16;
            v4 += *(a1 + 8);
            a1 += 16;
            a1 = &off_140115F58;
            a3 = &off_140116000;
            sub_1400F3B20(a1, 53, a3);
        }
        if (v4 >= 0) {
            v_40 = a3;
            if (!((0 /* unresolved: flags == */))) {
                v2 = (__int64)a2;
                sub_14002EDF0(0, v4);
                a2 = (struct Struct_1_t *)v2;
                if (result == 0) {
                    sub_1400F3326(1, v4);
                    result = 1;
                }
                v_20 = v4;
                v_28 = result;
                v_30 = 0;
                v9 = a2->field_0;
                v2 = a2->field_8;
                if (v2 > v4) JUMPOUT(0x1400567d0);
                v11 = 0;
                v_38 = result;
                a1 = result + v11;
                sub_1400F27F0(a1, v9, v2);
                v11 += v2;
                v2 = v4;
                v2 -= v11;
                if (v8 != v_40) {
                    a1 = (int *)v_38;
                    a1 += v11;
                    do {
                        if (v2 == 0) JUMPOUT(0x140056799);
                        a2 = ptr2->field_0;
                        v6 = ptr2->field_8;
                        --v2;
                        *a1 = 46;
                        v2 -= v6;
                        if ((v2 < 0)) JUMPOUT(0x140056799);
                        i = a1 + v6;
                        ++i;
                        ++a1;
                        sub_1400F27F0(a1, a2, v6);
                        ptr2 += 16;
                        a1 = (int *)i;
                    } while (ptr2 != v10);
                }
                v4 -= v2;
                v_30 = v4;
                ptr->field_10 = v4;
                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                _mm_storeu_si128((__m128i *)ptr, xmm0);
                return _mm_cvtsi128_si64(xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        } else {
            sub_1400F3360();
            *(__int64 *)ptr = (__int64)(0);
            ptr->field_8 = 1;
            ptr->field_10 = 0;
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return result;
}