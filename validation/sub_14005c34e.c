// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[24];
    __int64 field_20; // offset 32
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[96];
    __int64 field_80; // offset 128
};

__int64 sub_14004F470();
__int64 sub_140062B40();
__int64 sub_1400F84B0();
__int64 sub_1400F27F0();
__int64 sub_1400F27F6();
__int64 sub_14005EE7C();
__int64 sub_140063020();
__int64 sub_1400632B0();
__int64 sub_14005B1B7();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14005C34E() {
    __int64 rsp;
    __int64 arg_10;
    __int64 arg_18;
    __int64 arg_20;
    int arg_40;
    int v_1e0;
    int v_1f0;
    int v_1f8;
    __int64 v_200;
    int v_208;
    __int64 v_210;
    int v_218;
    __int64 v_228;
    __int64 v_240;
    __int64 v_258;
    int v_28;
    int v_2d0;
    int v_2d8;
    int v_2e0;
    int v_2e8;
    int v_2f0;
    int v_2f8;
    int v_300;
    __int64 v_38;
    int v_40;
    int v_48;
    int v_488;
    int v_490;
    int v_498;
    int v_4a0;
    int v_4a8;
    int v_4b0;
    int v_70;
    __int64 v_7d0;
    __int64 v_7d8;
    __int64 *i;
    __int64 v4;
    __int64 v6;
    __int64 *v2;
    __int64 v11;
    __int64 i2;
    __int64 v13;
    __int64 v14;
    struct Struct_1_t *result;
    __int64 v15;
    __int64 v10;
    __m128i xmm0;
    __int64 v9;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    struct Struct_2_t *ptr;
    __int64 v8;
    __int64 v7;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_1f0 = 8;
    i = rsp + 480;
    sub_14004F470(i);
    arg_10 = v14;
    arg_18 = v13;
    v_488 = 0;
    v_490 = 8;
    v_498 = 0;
    i = rsp + 720;
    sub_140062B40(i, v15);
    if (v_2d0 != 12) {
        i = rsp + 0x488;
        sub_1400F84B0(i);
        i = (__int64 *)v_490;
        v4 = rsp + 720;
        v6 = 176;
        v_38 = (__int64)i;
        sub_1400F27F0(i, v4, 176);
        v_498 = 1;
        v2 = (__int64 *)arg_10;
        v11 = arg_18;
        if (v11 == 0) JUMPOUT(0x14005e809);
        i2 = 1;
        v13 = rsp + 112;
        v14 = rsp + 0x488;
        do {
            if (*v2 != 44) JUMPOUT(0x14005ee7f);
            result = v2 + 1;
            i = v11 - 1;
            arg_10 = (__int64)result;
            arg_18 = (__int64)i;
            sub_140062B40(v13, v15);
            if (v_70 == 12) JUMPOUT(0x14005ee4c);
            result = (struct Struct_1_t *)v_38;
            if (i2 == v_488) JUMPOUT(0x14005e11d);
            v_38 = (__int64)result;
            i = result + v6;
            sub_1400F27F6(i, v13, 176);
            ++i2;
            v_498 = i2;
            v2 = (__int64 *)arg_10;
            v11 = arg_18;
            v6 += 176;
        } while (v11 != 0);
        return sub_14005EE7C();
    } else {
        result = (struct Struct_1_t *)v_2d8;
        if (result != 1) {
            v15 = v_2e0;
            i2 = v_2e8;
            v2 = (__int64 *)v_2f0;
            v13 = v_2f8;
            v14 = 8;
            v10 = v_300;
            if (v_488 != 0) {
                v6 = v10;
                v11 = (__int64)result;
                off_140108030(1, v4);
                off_140108038(result, 0, v14);
                result = (struct Struct_1_t *)v11;
                v10 = v6;
            }
        } else {
            i = rsp + 728;
            arg_10 = v14;
            arg_18 = v13;
            sub_14004F470(i);
            i = 8;
            v14 = 0;
            i2 = 0;
            result = 0x8000000000000000;
            v_210 = (__int64)result;
            v_258 = 0;
            result = 0x8000000000000003;
            v_228 = (__int64)result;
            v_240 = (__int64)result;
            v_1e0 = 0;
            v_1f8 = v14;
            v_200 = (__int64)i;
            v_208 = i2;
            v_38 = (__int64)i;
            if (i2 == 0) {
                v2 = 0;
            } else {
                result = (struct Struct_1_t *)arg_18;
                if (result != 0) {
                    i = (__int64 *)arg_10;
                    if (*i != 44) {
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)&v_4a0, xmm0);
                        v_488 = 1;
                        v_490 = 0;
                        v_498 = 8;
                        i = rsp + 0x488;
                        sub_14004F470(i);
                        v2 = 0;
                    } else {
                        ++i;
                        --result;
                        arg_10 = (__int64)i;
                        arg_18 = (__int64)result;
                        v2 = 1;
                    }
                    v_258 = (__int64)v2;
                    i = rsp + 0x488;
                    sub_140063020(i, v15);
                    result = (struct Struct_1_t *)v_488;
                    v6 = v15;
                    v15 = v_490;
                    v11 = v_498;
                    if (result != 3) {
                        v2 = (__int64 *)v_4a0;
                        v13 = v_4a8;
                        v14 = v_4b0;
                        i = rsp + 480;
                        v6 = (__int64)result;
                        sub_1400632B0(i);
                        result = (struct Struct_1_t *)v6;
                        v10 = v14;
                        i2 = v11;
                        v11 = 2;
                        if (result != 1) v11 = result;
                        v6 = v_28;
                        result = (struct Struct_1_t *)arg_20;
                        --result;
                        arg_20 = (__int64)result;
                        v6 = v15;
                    } else {
                        v_218 = v15;
                        result = (struct Struct_1_t *)v_218;
                        v_7d0 = (__int64)result;
                        result = (struct Struct_1_t *)v11;
                        v_7d8 = (__int64)result;
                        v13 = arg_18;
                        if (v13 == 0) JUMPOUT(0x14005e65c);
                        v15 = v6;
                        result = (struct Struct_1_t *)arg_10;
                        if (result->field_0 != 93) JUMPOUT(0x14005e65c);
                        i = (__int64 *)result;
                        result = 0x8000000000000002;
                        v10 = v_38;
                        ++i;
                        --v13;
                        arg_10 = (__int64)i;
                        arg_18 = v13;
                        v11 = 3;
                        i = 1;
                        v6 = 93;
                        v15 = 0;
                        v_1e0 = 0;
                        v_1f0 = 0;
                        v_1f8 = v14;
                        v_200 = v10;
                        v_208 = i2;
                        v_210 = (__int64)result;
                        xmm0 = _mm_load_si128((__m128i *)&v_7d0);
                        _mm_storeu_si128((__m128i *)&v_218, xmm0);
                        v4 = 0x8000000000000003;
                        v_228 = v4;
                        v_240 = v4;
                        v_258 = (__int64)v2;
                        if (i == 0) {
                            i = rsp + 480;
                            sub_1400632B0(i, 56, 48, 40);
                            result = (struct Struct_1_t *)v_28;
                            result->field_20 = result->field_20 - 1;
                            v2 = 2;
                            i2 = v_48;
                            v10 = v_40;
                            ptr->field_8 = v11;
                            v15 &= -256;
                            result = (struct Struct_1_t *)v6;
                            result = (struct Struct_1_t *)((__int64)(__int64)result | v15);
                            ptr->field_10 = result;
                            i = 8;
                            v9 = 24;
                            v14 = i2;
                            i2 = v13;
                            result = (struct Struct_1_t *)v10;
                        } else {
                            i = rsp + 536;
                            v4 = arg_40;
                            ptr->field_80 = v4;
                            xmm0 = _mm_loadu_si128((__m128i *)i);
                            xmm1 = _mm_loadu_si128((__m128i *)(i + 16));
                            xmm2 = _mm_loadu_si128((__m128i *)(i + 32));
                            xmm3 = _mm_loadu_si128((__m128i *)(i + 48));
                            _mm_storeu_si128((__m128i *)(ptr + 112), xmm3);
                            _mm_storeu_si128((__m128i *)(ptr + 96), xmm2);
                            _mm_storeu_si128((__m128i *)(ptr + 80), xmm1);
                            _mm_storeu_si128((__m128i *)(ptr + 64), xmm0);
                            i = (__int64 *)v_28;
                            --arg_20;
                            ptr->field_8 = 0;
                            ptr->field_10 = v11;
                            ptr->field_18 = 0;
                            i = 7;
                            v9 = 32;
                            v2 = (__int64 *)v10;
                        }
                        *(__int64 *)(ptr + v9) = (__int64)(v14);
                        *(__int64 *)(ptr + v8) = (__int64)(v2);
                        *(__int64 *)(ptr + v7) = (__int64)(i2);
                        *(__int64 *)(ptr + v4) = (__int64)(result);
                        *(__int64 *)ptr = (__int64)(i);
                        return sub_14005B1B7();
                    }
                    return (__int64)v2;
                }
                return (__int64)v2;
            }
            return (__int64)v2;
        }
        return (__int64)result;
    }
}