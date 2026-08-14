// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[16];
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_140037300();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114588;

__int64 __fastcall sub_140044330(int a1, int *a2, int a3) {
    __int64 rsp;
    int v_10;
    __int64 v_18;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_8;
    __int64 *dst;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *dst2;
    __int64 *dst3;
    __int64 v8;
    __int64 *result;
    __int64 v2;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v10;
    __int64 v5;

    dst = rsp + 128;
    *dst = -2;
    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 984);
    if (result == 0) {
        sub_1400F3340(8, 984);
    } else {
        dst2 = result;
        *(result + 352) = 0;
        dst3 = ptr2->field_0;
        v8 = ptr2->field_10;
        result = *(dst3 + 978);
        v2 = v8;
        v2 = ~v2;
        v2 += (__int64)result;
        *(dst2 + 978) = v2;
        result = v8 * 56;
        a1 = *(__int64 *)((__int64)dst3 + (__int64)result + 408);
        v_20 = a1;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 360));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 376));
        xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 392));
        _mm_store_si128((__m128i *)&v_30, xmm2);
        _mm_store_si128((__m128i *)&v_40, xmm1);
        _mm_store_si128((__m128i *)&v_50, xmm0);
        result = (__int64 *)v8;
        result = (__int64 *)((__int64)(__int64)result << 5);
        a1 = *(__int64 *)((__int64)dst3 + (__int64)result);
        a2 = *(__int64 *)((__int64)dst3 + (__int64)result + 8);
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 16));
        _mm_store_si128((__m128i *)&v_60, xmm0);
        v_8 = (int)a2;
        v_10 = a1;
        if (v2 < 12) {
            result = dst3 + 360;
            v10 = v8 + 1;
            a1 = (int)dst2;
            a1 += 360;
            a2 = v10 * 56;
            a2 = (int *)((__int64)a2 + (__int64)result);
            a3 = v2 * 56;
            sub_1400F27F0(a1, a2, a3);
            v10 <<= 5;
            v10 += (__int64)dst3;
            v2 <<= 5;
            sub_1400F27F0(dst2, v10, v2);
            *(dst3 + 978) = v8;
            xmm0 = _mm_load_si128((__m128i *)&v_50);
            xmm1 = _mm_load_si128((__m128i *)&v_40);
            xmm2 = _mm_load_si128((__m128i *)&v_30);
            _mm_storeu_si128((__m128i *)ptr, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
            _mm_storeu_si128((__m128i *)(ptr + 32), xmm2);
            result = (__int64 *)v_20;
            ptr->field_30 = result;
            xmm0 = _mm_load_si128((__m128i *)&v_60);
            _mm_storeu_si128((__m128i *)(ptr + 72), xmm0);
            result = ptr2->field_8;
            ptr->field_58 = dst3;
            ptr->field_60 = result;
            result = (__int64 *)v_10;
            ptr->field_38 = result;
            result = (__int64 *)v_8;
            ptr->field_40 = result;
            ptr->field_68 = dst2;
            ptr->field_70 = 0;
            return (__int64)result;
        }
    }
    v_18 = (__int64)dst2;
    v5 = &off_140114588;
    sub_1400F3600(0, v2, 11, v5);
    v_10 = v2;
    dst = v2 + 128;
    if (v_10 != 0) {
        off_140108030();
        off_140108038(result, 0, v_8);
    }
    a1 = dst - 80;
    sub_140037300(a1);
    off_140108030();
    return off_140108038(result, 0, v_18);
}