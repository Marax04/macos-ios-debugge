// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[136];
    __int64 field_A8; // offset 168
};

__int64 sub_140054CF0();
__int64 sub_140046190();
__int64 sub_140054AA0();
__int64 sub_14005A9A0();
__int64 sub_1400617D0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140063420(__int64 *a1, int *a2) {
    __int64 rsp;
    int arg_10;
    __int64 arg_18;
    int v_100;
    int v_110;
    int v_120;
    int v_130;
    int v_140;
    int v_150;
    int v_160;
    int v_170;
    __int64 v_180;
    int v_190;
    int v_1a0;
    __int64 v_1e0;
    int v_1e8;
    int v_1f0;
    int v_1f8;
    int v_200;
    int v_208;
    int v_218;
    int v_228;
    int v_238;
    int v_248;
    int v_258;
    int v_268;
    int v_278;
    int v_28;
    int v_288;
    int v_290;
    int v_2d0;
    int v_2e0;
    int v_30;
    int v_38;
    int v_39;
    int v_3d;
    int v_3f;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_68;
    int v_78;
    int v_88;
    int v_98;
    int v_a8;
    int v_b8;
    int v_c8;
    int v_d8;
    int v_e0;
    int v_f8;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v8;
    __int64 v4;
    __int64 v7;
    __m128i xmm0;
    __int64 *result;
    __int64 v5;
    __int64 v2;
    __m128i xmm1;
    __int64 v10;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v6;

    src = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    a1 = rsp + 48;
    sub_140054CF0(a1);
    i = v_30;
    v8 = v_38;
    v4 = v_40;
    v7 = v_48;
    if (i != 3) {
        xmm0 = _mm_loadu_si128((__m128i *)&v_50);
        _mm_store_si128((__m128i *)&v_100, xmm0);
    } else {
        result = (__int64 *)arg_18;
        v_f8 = v8;
        if (result == 0) {
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_48, xmm0);
            v_38 = 0;
            v_3f = 0;
            v_3d = 0;
            v_39 = 0;
            src = rsp + 64;
            v_40 = 8;
            v8 = v_38;
        } else {
            a1 = (__int64 *)arg_10;
            a2 = *a1;
            v5 = result - 1;
            i = a1 + 1;
            arg_10 = i;
            arg_18 = v5;
            if (a2 != 61) {
                arg_10 = (int)a1;
                arg_18 = (__int64)result;
                xmm0 = _mm_setzero_si128();
                _mm_storeu_si128((__m128i *)&v_48, xmm0);
                src = rsp + 64;
                v_40 = 8;
                v8 = 0;
                v2 = rsp + 488;
                xmm0 = _mm_loadu_si128((__m128i *)src);
                xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
                _mm_storeu_si128((__m128i *)&v_1f8, xmm1);
                _mm_storeu_si128((__m128i *)&v_1e8, xmm0);
                v_1e0 = v8;
                i = v_1f0;
                if (i == v8) JUMPOUT(0x140063943);
                result = (__int64 *)v_1e8;
                a1 =  + i*2;
                a1 += i;
                a2 = 0x2E00000000;
                result[(__int64)a1] = a2;
                ++i;
                v_1f0 = i;
                xmm0 = _mm_loadu_si128((__m128i *)v2);
                xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                _mm_store_si128((__m128i *)&v_2d0, xmm0);
                _mm_store_si128((__m128i *)&v_2e0, xmm1);
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                _mm_storeu_si128((__m128i *)src, xmm0);
                src = rsp + 64;
                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                _mm_storeu_si128((__m128i *)&v_1e8, xmm0);
                _mm_storeu_si128((__m128i *)&v_1f8, xmm1);
                v_1e0 = v8;
                i = v_1f0;
                if (i == v8) JUMPOUT(0x14006395d);
                result = (__int64 *)v_1e8;
                a1 =  + i*2;
                a1 += i;
                a2 = 0x3D00000000;
                result[(__int64)a1] = a2;
                ++i;
                v_1f0 = i;
                xmm0 = _mm_loadu_si128((__m128i *)v2);
                xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
                _mm_storeu_si128((__m128i *)(src + 16), xmm1);
                _mm_storeu_si128((__m128i *)src, xmm0);
                src = (__int64 *)v_40;
                v10 = v_48;
                xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                _mm_store_si128((__m128i *)&v_190, xmm0);
                _mm_store_si128((__m128i *)&v_30, xmm0);
                i = 2;
                xmm0 = _mm_load_si128((__m128i *)&v_30);
                _mm_store_si128((__m128i *)&v_100, xmm0);
                if (v7 != 0) {
                    v2 = v4;
                    do {
                        sub_140046190(v2, a2, v5, v6);
                        v2 += 144;
                        --v7;
                    } while ((v7 != 0));
                } else {
                }
                if (v_f8 != 0) {
                    off_140108030();
                    off_140108038(result, 0, v4);
                }
                v4 = (__int64)src;
                v7 = v10;
                xmm0 = _mm_load_si128((__m128i *)&v_100);
                _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
                *(__int64 *)ptr = (__int64)(i);
                ptr->field_8 = v8;
                ptr->field_10 = v4;
                ptr->field_18 = v7;
                ptr->field_A8 = 12;
                return _mm_cvtsi128_si64(xmm0);
            } else {
                v10 = *src;
                v_1e0 = 0;
                v_1f0 = 0;
                v_1f8 = 0x920;
                a1 = rsp + 48;
                a2 = rsp + 480;
                sub_140054AA0(a1, a2, src);
                v2 = v_30;
                if (v2 != 3) {
                    v8 = v_38;
                    src = (__int64 *)v_40;
                    v10 = v_48;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                    _mm_store_si128((__m128i *)&v_e0, xmm0);
                } else {
                    v_28 = v10;
                    v2 = arg_10;
                    v2 -= *src;
                    a1 = rsp + 48;
                    sub_14005A9A0(a1, src);
                    result = (__int64 *)v_30;
                    v5 = v_38;
                    v8 = v_40;
                    a2 = (int *)v_48;
                    v10 = v_50;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_58);
                    _mm_store_si128((__m128i *)&v_290, xmm0);
                    if (result != 8) {
                        a1 = (__int64 *)v_d8;
                        v_288 = (int)a1;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_c8);
                        _mm_storeu_si128((__m128i *)&v_278, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
                        _mm_storeu_si128((__m128i *)&v_268, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
                        _mm_storeu_si128((__m128i *)&v_258, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                        xmm1 = _mm_loadu_si128((__m128i *)&v_78);
                        xmm2 = _mm_loadu_si128((__m128i *)&v_88);
                        xmm3 = _mm_loadu_si128((__m128i *)&v_98);
                        _mm_storeu_si128((__m128i *)&v_248, xmm3);
                        _mm_storeu_si128((__m128i *)&v_238, xmm2);
                        _mm_storeu_si128((__m128i *)&v_228, xmm1);
                        v6 = arg_10;
                        v6 -= *src;
                        _mm_storeu_si128((__m128i *)&v_218, xmm0);
                        v_1e0 = (__int64)result;
                        v_1e8 = v5;
                        v_1f0 = v8;
                        v_1f8 = (int)a2;
                        v_200 = v10;
                        xmm0 = _mm_load_si128((__m128i *)&v_290);
                        _mm_storeu_si128((__m128i *)&v_208, xmm0);
                        a1 = rsp + 48;
                        a2 = rsp + 480;
                        sub_1400617D0(a1, a2, v2, v6);
                        v6 = v_30;
                        v5 = v_38;
                        v8 = v_40;
                        a1 = (__int64 *)v_48;
                        a2 = (int *)v_50;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_58);
                        _mm_store_si128((__m128i *)&v_1a0, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
                        _mm_store_si128((__m128i *)&v_110, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_78);
                        _mm_store_si128((__m128i *)&v_120, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_88);
                        _mm_store_si128((__m128i *)&v_130, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_98);
                        _mm_store_si128((__m128i *)&v_140, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
                        _mm_store_si128((__m128i *)&v_150, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
                        _mm_store_si128((__m128i *)&v_160, xmm0);
                        xmm0 = _mm_loadu_si128((__m128i *)&v_c8);
                        _mm_store_si128((__m128i *)&v_170, xmm0);
                        result = (__int64 *)v_d8;
                        v_180 = (__int64)result;
                        if (v6 != 8) JUMPOUT(0x140063977);
                        v10 = (__int64)a2;
                        src = a1;
                    } else {
                        src = (__int64 *)a2;
                        xmm0 = _mm_load_si128((__m128i *)&v_290);
                        _mm_store_si128((__m128i *)&v_1a0, xmm0);
                    }
                    xmm0 = _mm_load_si128((__m128i *)&v_1a0);
                    _mm_store_si128((__m128i *)&v_e0, xmm0);
                    v2 = v5;
                }
                xmm0 = _mm_load_si128((__m128i *)&v_e0);
                _mm_store_si128((__m128i *)&v_190, xmm0);
                _mm_store_si128((__m128i *)&v_30, xmm0);
                if (v2 != 2) i = v2;
                xmm0 = _mm_load_si128((__m128i *)&v_30);
                _mm_store_si128((__m128i *)&v_100, xmm0);
                if (v7 != 0) {
                    return _mm_cvtsi128_si64(xmm0);
                }
                return _mm_cvtsi128_si64(xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}