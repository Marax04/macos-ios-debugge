// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[15];
    __int64 field_F; // offset 15
    __int64 field_17; // offset 23
    char _pad_17[14];
    __int64 field_2D; // offset 45
    char _pad_2D[249];
    __int64 field_12E; // offset 302
};

__int64 sub_1400F27F0();
__int64 sub_1400F3869();
__int64 sub_14002EDF0();
__int64 sub_14006C3D0();
__int64 sub_14006C500();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3A8;
extern __int64 off_14011C190;
extern __int64 off_14011B7A0;
extern __int64 off_14011B7B0;

__int64 __fastcall sub_1400E01D0(int *a1, int a2, int a3) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_30;
    int v_40;
    int v_50;
    int v_60;
    int v_70;
    int v_80;
    int v_98;
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 v3;
    __m128i xmm0;
    __m128i xmm1;

    result = a3;
    ptr = (struct Struct_1_t *)a1;
    v_28 = 0;
    a1 = (int *)result;
    if (((__int64)a1 & 248) == 0) {
        *(__int64 *)(rsp + a1 + 40) = 0;
        a1 = (int *)result;
        if ((result & 0xF800) == 0) {
            a3 = result;
            a3 >>= 16;
            *(__int64 *)(rsp + a1 + 40) = 1;
            a1 = (int *)a3;
            if ((result & 0xF80000) == 0) {
                a3 = result;
                a3 >>= 24;
                *(__int64 *)(rsp + a1 + 40) = 2;
                a1 = (int *)a3;
                if ((result & 0xF8000000) == 0) {
                    a3 = result;
                    a3 >>= 32;
                    *(__int64 *)(rsp + a1 + 40) = 3;
                    a1 = (int *)a3;
                    a3 = 0xF800000000;
                    if ((result & a3) == 0) {
                        a3 = result;
                        a3 >>= 40;
                        *(__int64 *)(rsp + a1 + 40) = 4;
                        a1 = (int *)a3;
                        a3 = 0xF80000000000;
                        if ((result & a3) == 0) {
                            a3 = result;
                            a3 >>= 48;
                            *(__int64 *)(rsp + a1 + 40) = 5;
                            a1 = (int *)a3;
                            a3 = 0xF8000000000000;
                            if ((result & a3) == 0) {
                                a3 = result;
                                a3 >>= 56;
                                *(__int64 *)(rsp + a1 + 40) = 6;
                                result >>= 59;
                                if ((result != 0)) {
                                } else {
                                    *(__int64 *)(rsp + a3 + 40) = 7;
                                    a1 = ptr + 46;
                                    sub_1400F27F0(a1, a2, 256);
                                    result = v_28;
                                    ptr->field_12E = result;
                                    *(__int64 *)ptr = (__int64)(0);
                                    ptr->field_2D = 0;
                                    return result;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    a3 = &off_14011B3A8;
    sub_1400F3869(a3, 8, a3);
    v3 = (__int64)a1;
    sub_14002EDF0(0, 31);
    if (result == 0) JUMPOUT(0x1400e03bc);
    ptr = (struct Struct_1_t *)result;
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011C190);
    _mm_storeu_si128((__m128i *)result, xmm0);
    result = 0x3236762E6B73616D;
    ptr->field_F = result;
    ptr->field_17 = v3;
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_50, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    _mm_store_si128((__m128i *)&v_20, xmm0);
    xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7A0);
    _mm_store_si128((__m128i *)&v_60, xmm1);
    xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7B0);
    _mm_store_si128((__m128i *)&v_70, xmm1);
    _mm_store_si128((__m128i *)&v_80, xmm0);
    v3 = rsp + 32;
    sub_14006C3D0(v3, ptr, 31);
    a1 = rsp + 152;
    sub_14006C500(a1, v3);
    v3 = v_98;
    off_140108030();
    off_140108038(result, 0, ptr);
    result = 0xA5C35A3C;
    if (v3 != 0) result = v3;
    return result;
}