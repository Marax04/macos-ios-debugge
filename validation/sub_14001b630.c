// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2056];
    __int64 field_808; // offset 0x808
    __int64 field_810; // offset 0x810
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    char _pad_100[120];
    __int64 field_180; // offset 384
};

__int64 sub_1400F1D90();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3A38();
__int64 sub_1400F3600();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140110048;
extern __int64 off_140110058;
extern __int64 off_14001B910;
extern __int64 off_14010FF28;
extern __int64 off_14010FF38;
extern __int64 off_14010FFA8;
extern __int64 off_140110090;

__int64 __fastcall sub_14001B630(int *a1, int *a2) {
    __int64 rsp;
    int arg_8;
    int arg_810;
    int v_1030;
    int v_1040;
    __int64 v_20;
    int v_30;
    int v_40;
    int v_50;
    int str;
    int v_828;
    int v_830;
    int v_838;
    char *str2;
    struct Struct_1_t *result;
    __int64 v4;
    __int64 *src;
    __int64 v7;
    __int64 *dst;
    __int64 v11;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_2_t *ptr;
    __int64 v12;
    __int64 v9;
    __int64 v5;
    __int64 v6;
    __int64 v8;

    sub_1400F1D90(0x1058);
    _mm_store_si128((__m128i *)&v_1040, xmm7);
    _mm_store_si128((__m128i *)&v_1030, xmm6);
    result = (struct Struct_1_t *)a1;
    result = (struct Struct_1_t *)((__int64)(__int64)result & 120);
    v_20 = (__int64)result;
    if (!((result != 0))) {
        v4 = (__int64)a2;
        src = (__int64 *)a1;
        if (a2 == 0) {
            v4 = *(src + 0x810);
            if (v4 < 65) {
                if (v4 != 0) {
                    v7 = src + 16;
                    v4 <<= 5;
                    dst = rsp + 0x828;
                    v11 = 0;
                    xmm6 = _mm_loadu_si128((__m128i *)&off_140110048);
                    xmm7 = _mm_loadu_si128((__m128i *)&off_140110058);
                    for (; v4 != v11; v11 += 32) {
                        xmm0 = _mm_loadu_si128((__m128i *)(v7 + v11));
                        xmm1 = _mm_loadu_si128((__m128i *)(v7 + v11 + 16));
                        _mm_store_si128((__m128i *)&v_830, xmm1);
                        _mm_store_si128((__m128i *)&str2, xmm0);
                        _mm_storeu_si128((__m128i *)(v7 + v11), xmm6);
                        _mm_storeu_si128((__m128i *)(v7 + v11 + 16), xmm7);
                        ((__int64 (*)())(str2))();
                    }
                }
                src = *(src - 8);
                off_140108030(dst, a2, v5);
                off_140108038(result, 0, src);
                xmm6 = _mm_load_si128((__m128i *)&v_1030);
                xmm7 = _mm_load_si128((__m128i *)&v_1040);
                return _mm_cvtsi128_si64(xmm7);
            }
        } else {
            dst = v4 + 16;
            result = (struct Struct_1_t *)arg_810;
            if (result >= 64) {
                xmm6 = _mm_loadu_si128((__m128i *)&off_140110058);
                xmm7 = _mm_loadu_si128((__m128i *)&off_140110048);
                v11 = rsp + 32;
                do {
                    ptr = (struct Struct_2_t *)arg_8;
                    result = 96;
                    do {
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 48), xmm6);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 64), xmm7);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 32), xmm7);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 16), xmm6);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result), xmm7);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 16), xmm6);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 32), xmm7);
                        _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 48), xmm6);
                        result += 128;
                    } while (result != 0x860);
                    sub_1400F27F0(str2, dst, 0x808);
                    sub_1400F27F0(dst, v11, 0x800);
                    arg_810 = 0;
                    *(__int64 *)rsp = *(__int64 *)rsp | 0;
                    v12 = ptr->field_180;
                    sub_14002EDF0(0, 0x818);
                    if (result != 0) {
                        v9 = (__int64)result;
                        sub_1400F27F0(result, str2, 0x808);
                        result->field_808 = v12;
                        result->field_810 = 0;
                        do {
                            a1 = ptr->field_100;
                            a2 = a1;
                            a2 = (int *)((__int64)(__int64)a2 & -8);
                            v5 = a2[258];
                            result = (struct Struct_1_t *)a1;
                            /* cmpxchg %v5, 256(%(__int64)ptr) */;
                        } while (true);
                        result = (struct Struct_1_t *)a1;
                        /* cmpxchg %v9, 256(%(__int64)ptr) */;
                        result = (struct Struct_1_t *)arg_810;
                        result = (struct Struct_1_t *)((__int64)(__int64)result << 5);
                        a1 = &off_14001B910;
                        *(__int64 *)((__int64)dst + (__int64)result) = a1;
                        *(__int64 *)((__int64)dst + (__int64)result + 8) = src;
                        ++arg_810;
                        return arg_810;
                    }
                    sub_1400F3340(8, 0x818);
                    result = &off_14010FF28;
                    str2 = (char *)result;
                    v_828 = 1;
                    v_830 = 8;
                    xmm0 = _mm_setzero_si128();
                    _mm_storeu_si128((__m128i *)&v_838, xmm0);
                    a2 = &off_14010FF38;
                    v6 = &off_14010FFA8;
                    a1 = rsp + 32;
                    v5 = rsp + 0x820;
                    sub_1400F3A38(a1, a2, v5, v6);
                    v6 = &off_140110090;
                    sub_1400F3600(0, v4, 64, v6);
                    _mm_store_si128((__m128i *)&v_50, xmm7);
                    _mm_store_si128((__m128i *)&v_40, xmm6);
                    dst = *a1;
                    dst = (__int64 *)((__int64)(__int64)dst & -128);
                    src = (__int64 *)arg_810;
                    if (src >= 65) JUMPOUT(0x14001b9be);
                    if (src != 0) {
                        v8 = dst + 16;
                        src = (__int64 *)((__int64)(__int64)src << 5);
                        v4 = rsp + 40;
                        v11 = 0;
                        xmm6 = _mm_loadu_si128((__m128i *)&off_140110048);
                        xmm7 = _mm_loadu_si128((__m128i *)&off_140110058);
                        for (; src != v11; v11 += 32) {
                            xmm0 = _mm_loadu_si128((__m128i *)(v8 + v11));
                            xmm1 = _mm_loadu_si128((__m128i *)(v8 + v11 + 16));
                            _mm_store_si128((__m128i *)&v_30, xmm1);
                            _mm_store_si128((__m128i *)&v_20, xmm0);
                            _mm_storeu_si128((__m128i *)(v8 + v11), xmm6);
                            _mm_storeu_si128((__m128i *)(v8 + v11 + 16), xmm7);
                            ((__int64 (*)())(v_20))();
                        }
                    }
                    src = (__int64 *)str;
                    off_140108030(v4);
                    off_140108038(result, 0, src);
                    xmm6 = _mm_load_si128((__m128i *)&v_40);
                    xmm7 = _mm_load_si128((__m128i *)&v_50);
                    return _mm_cvtsi128_si64(xmm7);
                } while (result >= 64);
            }
            return _mm_cvtsi128_si64(xmm7);
        }
        return _mm_cvtsi128_si64(xmm7);
    }
    return (__int64)result;
}