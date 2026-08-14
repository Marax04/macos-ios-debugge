// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140011760();
__int64 sub_14000ECF0();
__int64 sub_1400F3600();
__int64 sub_1400F6B10();
__int64 sub_1400F37A0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140028030;
extern __int64 off_140018400;
extern __int64 off_140027F90;
extern __int64 off_140113F88;
extern __int64 off_140112630;
extern __int64 off_140113F60;
extern __int64 off_140112578;
extern __int64 off_140112588;

__int64 __fastcall sub_1400294B2() {
    int arg_10;
    int arg_1a8;
    int arg_1b0;
    __int64 arg_1b8;
    int arg_1c0;
    int arg_1c8;
    int arg_1e8;
    __int64 arg_1f0;
    int arg_1f8;
    __int64 arg_200;
    int arg_208;
    int arg_210;
    __int64 arg_230;
    int arg_238;
    __int64 arg_240;
    __int64 arg_248;
    int arg_250;
    int arg_258;
    __int64 arg_260;
    int arg_268;
    __int64 arg_270;
    int arg_278;
    __int64 arg_288;
    __int64 arg_290;
    __int64 arg_298;
    int arg_38;
    int arg_48;
    int arg_7;
    int arg_8;
    int v_1;
    int v_10;
    int v_8;
    char *str;
    __int64 v2;
    __int64 *src;
    __int64 *result;
    __int64 v10;
    __int64 v11;
    __int64 v9;
    __int64 v4;
    __int64 v3;
    __int64 v7;
    __int64 v8;
    __m128i xmm0;
    __int64 v12;
    struct Struct_1_t *ptr;

    *result = *result + (__int64)result;
    v2 = ptr->field_0;
    src = ptr->field_8;
    result = v12 + 544;
    arg_230 = (__int64)result;
    v10 = &off_140028030;
    arg_238 = v10;
    result = v12 + 640;
    arg_240 = (__int64)result;
    result = &off_140018400;
    arg_248 = (__int64)result;
    arg_250 = v2;
    v11 = &off_140027F90;
    arg_258 = v11;
    arg_260 = (__int64)src;
    arg_268 = v10;
    v9 = &off_140113F88;
    arg_1a8 = v9;
    arg_1b0 = 5;
    arg_1c8 = 0;
    arg_1b8 = (__int64)str;
    arg_1c0 = 4;
    result = v12 + 472;
    arg_270 = (__int64)result;
    arg_278 = 0;
    v4 = &off_140112630;
    v3 = v12 + 624;
    v7 = v12 + 424;
    sub_140011760(v3, v4, v7);
    v3 = arg_278;
    if (result == 0) {
        result = (__int64 *)v3;
        result = (__int64 *)((__int64)(__int64)result & 3);
        if (result == 1) {
            result = v3 - 1;
            arg_288 = (__int64)result;
            result = (__int64 *)v_1;
            arg_298 = (__int64)result;
            result = (__int64 *)arg_7;
            arg_290 = (__int64)result;
            result = *result;
            if (result != 0) {
                v3 = arg_298;
                ((__int64 (*)())result)(v3);
            }
            v3 = arg_298;
            result = (__int64 *)arg_290;
            if (arg_8 != 0) {
                v4 = arg_10;
                sub_14000ECF0(v3, v4);
            }
            off_140108030();
            v7 = arg_288;
            off_140108038(result, 0, v7);
            v7 = arg_1e8;
            if (v7 >= 513) {
                v8 = &off_140113F60;
                sub_1400F3600(0, v7, 512, v8);
                sub_1400F6B10();
                result = &off_140112578;
                arg_1f0 = (__int64)result;
                arg_1f8 = 1;
                arg_200 = 8;
                xmm0 = _mm_setzero_si128();
                _mm_storeu_si128((__m128i *)&arg_208, xmm0);
                v4 = &off_140112588;
                v3 = v12 + 496;
                sub_1400F37A0(v3, v4);
                v_10 = v4;
                v12 = v4 + 128;
                v3 = arg_298;
                result = (__int64 *)arg_288;
                if (arg_8 != 0) {
                    result = (__int64 *)arg_288;
                    v4 = arg_10;
                    sub_14000ECF0(v3, v4);
                }
                off_140108030();
                v7 = arg_290;
                return off_140108038(result, 0, v7);
            }
        } else {
            v7 = arg_1e8;
            if (v7 >= 513) {
                return v7;
            }
        }
        v3 = ptr->field_10;
        result = ptr->field_18;
        v4 = v12 - 88;
        ((__int64 (*)())(arg_38))();
        v3 = (__int64)result;
        v3 &= 3;
        if (v3 == 1) {
            v3 = (__int64)result;
            --result;
            arg_290 = (__int64)result;
            result = (__int64 *)v_1;
            arg_298 = (__int64)result;
            result = (__int64 *)arg_7;
            arg_288 = (__int64)result;
            result = *result;
            if (result != 0) {
                v3 = arg_298;
                ((__int64 (*)())result)(v3, v4, v7);
            }
            src = (__int64 *)arg_298;
            result = (__int64 *)arg_288;
            if (arg_8 != 0) {
                ptr = (struct Struct_1_t *)arg_290;
                if (arg_10 >= 17) {
                    src = *(src - 8);
                }
                off_140108030();
                off_140108038(result, 0, src);
            } else {
                ptr = (struct Struct_1_t *)arg_290;
            }
            off_140108030();
            off_140108038(result, 0, ptr);
        }
        return (__int64)ptr;
    } else {
        if (v3 != 0) {
            result = (__int64 *)v3;
            result = (__int64 *)((__int64)(__int64)result & 3);
            if (result == 1) {
                result = v3 - 1;
                arg_288 = (__int64)result;
                result = (__int64 *)v_1;
                arg_298 = (__int64)result;
                result = (__int64 *)arg_7;
                arg_290 = (__int64)result;
                result = *result;
                if (result != 0) {
                    v3 = arg_298;
                    ((__int64 (*)())result)(v3);
                }
                result = (__int64 *)arg_298;
                v3 = arg_290;
                if (arg_8 != 0) {
                    if (arg_10 >= 17) {
                        result = (__int64 *)v_8;
                        arg_298 = (__int64)result;
                    }
                    off_140108030(v3);
                    off_140108038(result, 0, arg_298);
                }
                off_140108030();
                off_140108038(result, 0, arg_288);
            }
            v3 = ptr->field_10;
            result = ptr->field_18;
            result = (__int64 *)arg_48;
            v4 = v12 + 544;
            arg_230 = v4;
            arg_238 = v10;
            v4 = v12 + 640;
            arg_240 = v4;
            v4 = &off_140018400;
            arg_248 = v4;
            arg_250 = v2;
            arg_258 = v11;
            arg_260 = (__int64)src;
            arg_268 = v10;
            arg_1f0 = v9;
            arg_1f8 = 5;
            arg_210 = 0;
            arg_200 = (__int64)str;
            arg_208 = 4;
            v4 = v12 + 496;
            ((__int64 (*)())result)(v3, v4);
            v3 = (__int64)result;
            v3 &= 3;
            if (v3 == 1) {
                v3 = (__int64)result;
                --result;
                arg_290 = (__int64)result;
                result = (__int64 *)v_1;
                arg_298 = (__int64)result;
                result = (__int64 *)arg_7;
                arg_288 = (__int64)result;
                result = *result;
                if (result != 0) {
                    ((__int64 (*)())result)(arg_298);
                }
                src = (__int64 *)arg_298;
                result = (__int64 *)arg_288;
                if (arg_8 == 0) {
                    return (__int64)result;
                } else {
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
    }
    return (__int64)result;
}