// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[344];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int16 field_3D0; // offset 976
    int field_3D2; // offset 978
    char _pad_3D2[2];
    __int64 field_3D8; // offset 984
};

__int64 sub_1400F37A0();
__int64 sub_14003F040();
__int64 sub_14000F850();
__int64 sub_14002F640();
__int64 sub_140041760();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_14003F04C();
__int64 sub_1400F3326();
__int64 sub_14003F042();
__int64 sub_14003F02F();
__int64 sub_140042B20();
__int64 sub_140042CD0();
__int64 sub_1400F3600();
__int64 off_1401081F0();
__int64 off_140108060();
__int64 off_140108030();
__int64 off_140108038();
__int64 off_1401081F8();
extern __int64 off_1400339F0;
extern __int64 off_140112D50;
extern __int64 off_140112D88;
extern __int64 off_140114E50;
extern __int64 off_140114E68;
extern __int64 off_140114E80;

__int64 __fastcall sub_14003E430(size_t *a1, size_t *a2) {
    __int64 arg_10;
    int arg_100;
    int arg_108;
    int arg_110;
    int arg_118;
    int arg_120;
    __int64 arg_130;
    __int64 arg_138;
    int arg_140;
    __int64 arg_148;
    __int64 arg_150;
    __int64 arg_158;
    int arg_160;
    int arg_165;
    int arg_166;
    int arg_167;
    int arg_168;
    int arg_170;
    __int64 arg_18;
    int arg_20;
    int arg_28;
    int arg_30;
    int arg_3d0;
    int arg_3d2;
    int arg_3d8;
    __int64 arg_40;
    __int64 arg_50;
    __int64 arg_58;
    __int64 arg_60;
    __int64 arg_68;
    __int64 arg_70;
    int arg_78;
    int arg_8;
    __int64 arg_80;
    int arg_90;
    __int64 arg_a0;
    int arg_a8;
    int arg_b8;
    __int64 arg_c0;
    int arg_c8;
    int arg_d0;
    int arg_d8;
    __int64 arg_e0;
    __int64 arg_e8;
    int arg_f0;
    __int64 arg_f8;
    __int64 v_10;
    int v_18;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    int src;
    __int64 *v_3d8;
    char *src2;
    __int64 *i;
    __int64 *result;
    __int64 v12;
    __int64 v4;
    __int64 *v2;
    struct Struct_1_t *ptr;
    __int64 *src3;
    __int64 v9;
    __int64 v5;
    __int64 v7;
    __int64 i2;
    __m128i xmm6;
    __m128i xmm0;
    __int64 v8;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    _mm_store_si128((__m128i *)&arg_170, xmm6);
    arg_168 = -2;
    i = (__int64 *)a1;
    result = a2[3];
    v12 = a2[2];
    a1 = (v12 != 0) ? 1 : 0;
    a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
    if (a1 != 1) {
        result = 0;
    } else {
        arg_c0 = 0;
        arg_d0 = 0;
        v_20 = (__int64)i;
        if (result == 0) {
            v_18 = (int)a2;
            off_1401081F0(a1);
            if (result == 0) {
                off_140108060();
                result = (__int64 *)((__int64)(__int64)result << 32);
                result = (__int64 *)((__int64)(__int64)result | 2);
                v_10 = (__int64)result;
                result = src2 - 16;
                arg_e0 = (__int64)result;
                result = &off_1400339F0;
                arg_e8 = (__int64)result;
                result = &off_140112D50;
                arg_50 = (__int64)result;
                arg_58 = 1;
                arg_70 = 0;
                result = src2 + 224;
                arg_60 = (__int64)result;
                arg_68 = 1;
                a2 = &off_140112D88;
                a1 = src2 + 80;
                sub_1400F37A0(a1, a2);
                return sub_14003F040();
            } else {
                arg_d8 = v12;
                v12 = src2 + 112;
                v4 = src2 + 224;
                v2 = src2 + 80;
                arg_148 = (__int64)result;
                ptr = (struct Struct_1_t *)result;
                while (ptr->field_0 != 0) {
                    src3 = (__int64 *)ptr;
                    a1 = -2;
                    a2 = 0;
                    do {
                        v9 = (__int64)a2;
                        result = (__int64 *)a1;
                        ++a2;
                        a1 += 2;
                    } while (*(src3 + v9*2) != 0);
                    a1 = v9 + v9;
                    ptr = (__int64)a1 + (__int64)src3;
                    ptr += 2;
                    if (v9 != 0) {
                        i = 0;
                        while (*(src3 + (__int64)(__int64)i*2 + 2) != 61) {
                            ++i;
                            result -= 2;
                        }
                        v5 = i + 1;
                        if (i < v9) {
                            sub_14000F850(v4, src3, v5);
                            i += 2;
                            v5 = v9;
                            v5 -= (__int64)i;
                            if (!((v5 < 0))) {
                                a2 =  + (__int64)(__int64)i*2;
                                a2 = (size_t *)((__int64)a2 + (__int64)src3);
                                sub_14000F850(v2, a2, v5);
                                v7 = arg_e0;
                                i2 = arg_e8;
                                xmm6 = _mm_loadu_si128((__m128i *)&arg_f0);
                                result = (__int64 *)arg_f0;
                                v5 = arg_50;
                                a2 = (size_t *)arg_58;
                                xmm0 = _mm_loadu_si128((__m128i *)(v12 - 16));
                                _mm_store_si128((__m128i *)&v_40, xmm0);
                                a1 = (size_t *)v7;
                                a1 = (size_t *)(-(__int64)a1);
                                if (!((0 /* overflow check on (-a1) */))) {
                                    arg_158 = v7;
                                    arg_150 = v5;
                                    arg_140 = (int)a2;
                                    result += i2;
                                    arg_e0 = i2;
                                    arg_e8 = (__int64)result;
                                    arg_f0 = 0;
                                    i = src2 - 16;
                                    arg_138 = i2;
                                    sub_14002F640(i, v4, v5, i2);
                                    result = (__int64 *)arg_158;
                                    arg_50 = (__int64)result;
                                    result = (__int64 *)arg_138;
                                    arg_58 = (__int64)result;
                                    _mm_storeu_si128((__m128i *)&arg_60, xmm6);
                                    result = *src2;
                                    arg_10 = (__int64)result;
                                    xmm0 = _mm_loadu_si128((__m128i *)&v_10);
                                    _mm_storeu_si128((__m128i *)v12, xmm0);
                                    result = (__int64 *)arg_150;
                                    arg_e0 = (__int64)result;
                                    result = (__int64 *)arg_140;
                                    arg_e8 = (__int64)result;
                                    xmm0 = _mm_load_si128((__m128i *)&v_40);
                                    result = src2 + 240;
                                    _mm_storeu_si128((__m128i *)result, xmm0);
                                    arg_166 = 0;
                                    a2 = src2 + 192;
                                    sub_140041760(i, a2, v2, v4);
                                    result = (__int64 *)v_10;
                                    result = (__int64 *)((__int64)(__int64)result << 1);
                                    i = (__int64 *)src;
                                    off_140108030();
                                    off_140108038(result, 0, i);
                                }
                                a1 = (size_t *)arg_148;
                                off_1401081F8(a1);
                                a2 = (size_t *)v_18;
                                v12 = arg_d8;
                                result = *a2;
                                v8 = arg_8;
                                v2 = (result != 0) ? 1 : 0;
                                if (result == 0) v12 = result;
                                v7 = 0;
                                ptr = 0;
                                while (v12 != 0) {
                                    if (((__int64)v2 & 1) == 0) JUMPOUT(0x14003f021);
                                    if (ptr == 0) {
                                        if (v8 == 0) {
                                            ptr = (struct Struct_1_t *)result;
                                            v9 = 0;
                                            result = 0;
                                            a1 = ptr->field_3D2;
                                            if (v8 < a1) {
                                                a1 = (size_t *)v8;
                                                v2 = (__int64 *)ptr;
                                                v8 = a1 + 1;
                                                if (result == 0) {
                                                    ptr = (struct Struct_1_t *)v2;
                                                    --v12;
                                                    result = (__int64)(__int64)a1 * 56;
                                                    v4 = (__int64)v2 + (__int64)result;
                                                    v4 += 360;
                                                    a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                                    if (!__OFSUB(v7, *(__int64 *)((__int64)v2 + (__int64)a1))) {
                                                        v2 = (__int64 *)((__int64)v2 + (__int64)a1);
                                                        src3 = (__int64 *)arg_10;
                                                        if (src3 < 0) JUMPOUT(0x14003f035);
                                                        i = (__int64 *)arg_8;
                                                        arg_d8 = v12;
                                                        if (src3 == 0) {
                                                            result = 1;
                                                            arg_158 = (__int64)result;
                                                            arg_150 = (__int64)src3;
                                                            sub_1400F27F0(result, i, src3);
                                                            src3 = (__int64 *)arg_30;
                                                            v12 =  + (__int64)(__int64)src3*2;
                                                            result = (src3 < 0) ? 1 : 0;
                                                            a1 = 0x7FFFFFFFFFFFFFFE;
                                                            a1 = (v12 > a1) ? 1 : 0;
                                                            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)result);
                                                            if (!((a1 != 0))) {
                                                                result = (__int64 *)arg_18;
                                                                arg_138 = (__int64)result;
                                                                a2 = (size_t *)arg_28;
                                                                if (v12 == 0) {
                                                                    v4 = 2;
                                                                    i = 0;
                                                                    sub_1400F27F0(v4, a2, v12);
                                                                    result = (__int64 *)arg_150;
                                                                    arg_50 = (__int64)result;
                                                                    a1 = (size_t *)arg_158;
                                                                    arg_58 = (__int64)a1;
                                                                    arg_60 = (__int64)result;
                                                                    result = (__int64 *)arg_138;
                                                                    arg_68 = (__int64)result;
                                                                    arg_70 = (__int64)i;
                                                                    arg_78 = v4;
                                                                    arg_80 = (__int64)src3;
                                                                    v12 = arg_10;
                                                                    arg_140 = v4;
                                                                    arg_148 = (__int64)i;
                                                                    if (v12 >= 0) {
                                                                        i = (__int64 *)arg_8;
                                                                        if (v12 == 0) {
                                                                            src3 = 1;
                                                                            sub_1400F27F0(src3, i, v12);
                                                                            result = (__int64 *)arg_18;
                                                                            arg_e0 = v12;
                                                                            arg_e8 = (__int64)src3;
                                                                            arg_f0 = v12;
                                                                            arg_f8 = (__int64)result;
                                                                            arg_165 = 0;
                                                                            a1 = src2 - 16;
                                                                            a2 = src2 + 192;
                                                                            v5 = src2 + 80;
                                                                            i2 = src2 + 224;
                                                                            sub_140041760(a1, a2, v5, i2);
                                                                            result = (__int64 *)v_10;
                                                                            result = (__int64 *)((__int64)(__int64)result << 1);
                                                                            v12 = arg_d8;
                                                                            v7 = 0;
                                                                            if (result == 0) {
                                                                                v2 = 1;
                                                                                result = 0;
                                                                            }
                                                                            i = (__int64 *)src;
                                                                            off_140108030();
                                                                            off_140108038(result, 0, i);
                                                                            v7 = 0;
                                                                            return v7;
                                                                        }
                                                                        sub_14002EDF0(0, v12);
                                                                        src3 = result;
                                                                        if (result != 0) {
                                                                            return (__int64)src3;
                                                                        }
                                                                        return sub_14003F04C();
                                                                    }
                                                                    arg_165 = 1;
                                                                    sub_1400F3326(0, v12);
                                                                    return sub_14003F040();
                                                                }
                                                                i = (__int64 *)a2;
                                                                sub_14002EDF0(0, v12);
                                                                a2 = (size_t *)i;
                                                                v4 = (__int64)result;
                                                                i = src3;
                                                                if (result != 0) {
                                                                    return (__int64)i;
                                                                }
                                                                return sub_14003F042();
                                                            }
                                                            sub_1400F3326(0, v12);
                                                            return sub_14003F040();
                                                        }
                                                        sub_14002EDF0(0, src3);
                                                        if (result != 0) {
                                                            return (__int64)i;
                                                        }
                                                        return sub_14003F02F();
                                                    }
                                                    src3 = (__int64 *)arg_c0;
                                                    v2 = 1;
                                                    result = 0;
                                                    i = (__int64 *)v12;
                                                    i2 = arg_28;
                                                    result = (__int64 *)arg_30;
                                                    v12 = arg_c8;
                                                    v_20 = (__int64)result;
                                                    a1 = src2 - 64;
                                                    sub_140042B20(a1, src3, v12, i2);
                                                    if (v_40 != 1) {
                                                        result = (__int64 *)v_38;
                                                        a2 = (size_t *)v_30;
                                                        a1 = (size_t *)v_28;
                                                        arg_167 = 0;
                                                        if (a2 == 0) {
                                                            arg_e0 = (__int64)result;
                                                            arg_e8 = 0;
                                                            arg_f0 = (int)a1;
                                                            a1 = src2 + 80;
                                                            a2 = src2 + 224;
                                                            v5 = src2 + 359;
                                                            sub_140042CD0(a1, a2, v5);
                                                            result = (__int64 *)arg_a0;
                                                            arg_130 = (__int64)result;
                                                            xmm0 = _mm_load_si128((__m128i *)&arg_90);
                                                            _mm_store_si128((__m128i *)&arg_120, xmm0);
                                                            xmm0 = _mm_load_si128((__m128i *)&arg_50);
                                                            xmm1 = _mm_load_si128((__m128i *)&arg_60);
                                                            xmm2 = _mm_load_si128((__m128i *)&arg_70);
                                                            xmm3 = _mm_load_si128((__m128i *)&arg_80);
                                                            _mm_store_si128((__m128i *)&arg_110, xmm3);
                                                            _mm_store_si128((__m128i *)&arg_100, xmm2);
                                                            --arg_d0;
                                                            _mm_store_si128((__m128i *)&arg_f0, xmm1);
                                                            _mm_store_si128((__m128i *)&arg_e0, xmm0);
                                                            if (arg_167 != 1) {
                                                                result = (__int64 *)arg_e0;
                                                                result = (__int64 *)(-(__int64)result);
                                                                v12 = (__int64)i;
                                                                v7 = 0;
                                                                v12 = arg_100;
                                                                result = (__int64 *)arg_108;
                                                                arg_150 = (__int64)result;
                                                                v4 = arg_118;
                                                                src3 = (__int64 *)arg_120;
                                                                if ((0 /* unresolved: flags >= */)) {
                                                                    if (v12 == 0) {
                                                                        v4 <<= 1;
                                                                        v12 = (__int64)i;
                                                                        off_140108030(0);
                                                                        off_140108038(result, 0, src3);
                                                                        v7 = 0;
                                                                        result = 0;
                                                                    }
                                                                    off_140108030();
                                                                    v5 = arg_150;
                                                                    off_140108038(result, 0, v5);
                                                                    v7 = 0;
                                                                    return v7;
                                                                }
                                                                arg_158 = (__int64)src3;
                                                                src3 = (__int64 *)arg_e8;
                                                                off_140108030(0);
                                                                src3 = (__int64 *)arg_158;
                                                                off_140108038(result, 0, src3);
                                                                v7 = 0;
                                                                return v7;
                                                            }
                                                            if (v12 == 0) JUMPOUT(0x14003eff9);
                                                            result = *(src3 + 984);
                                                            arg_c0 = (__int64)result;
                                                            --v12;
                                                            arg_c8 = v12;
                                                            arg_160 = 0;
                                                            off_140108030();
                                                            off_140108038(result, 0, src3);
                                                            return arg_160;
                                                        }
                                                        a1 = v_3d8[(__int64)a1];
                                                        result = (__int64 *)a2;
                                                        --result;
                                                        if ((result == 0)) {
                                                            result = a1[122];
                                                            --result;
                                                            v_58 = (int)a1;
                                                            v_50 = 0;
                                                            v_48 = (__int64)result;
                                                            a1 = src2 + 80;
                                                            a2 = src2 - 88;
                                                            v5 = src2 + 359;
                                                            sub_140042CD0(a1, a2, v5, i2);
                                                            result = (__int64 *)arg_a0;
                                                            arg_40 = (__int64)result;
                                                            xmm0 = _mm_loadu_si128((__m128i *)&arg_90);
                                                            _mm_store_si128((__m128i *)&arg_30, xmm0);
                                                            xmm0 = _mm_loadu_si128((__m128i *)&arg_50);
                                                            xmm1 = _mm_loadu_si128((__m128i *)&arg_60);
                                                            xmm2 = _mm_loadu_si128((__m128i *)&arg_70);
                                                            xmm3 = _mm_loadu_si128((__m128i *)&arg_80);
                                                            _mm_store_si128((__m128i *)&arg_20, xmm3);
                                                            _mm_store_si128((__m128i *)&arg_10, xmm2);
                                                            _mm_store_si128((__m128i *)&*src2, xmm1);
                                                            _mm_store_si128((__m128i *)&v_10, xmm0);
                                                            result = (__int64 *)arg_a8;
                                                            a1 = (size_t *)arg_b8;
                                                            a2 = (size_t *)arg_3d2;
                                                            if (a1 < a2) {
                                                                a2 = (__int64)(__int64)a1 * 56;
                                                                a1 = (size_t *)((__int64)(__int64)a1 << 5);
                                                                v5 = *(__int64 *)((__int64)result + (__int64)a2 + 408);
                                                                arg_110 = v5;
                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a2 + 360));
                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a2 + 376));
                                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a2 + 392));
                                                                _mm_store_si128((__m128i *)&arg_100, xmm2);
                                                                _mm_store_si128((__m128i *)&arg_f0, xmm1);
                                                                _mm_store_si128((__m128i *)&arg_e0, xmm0);
                                                                v5 = arg_20;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 408) = v5;
                                                                xmm0 = _mm_load_si128((__m128i *)&v_10);
                                                                xmm1 = _mm_load_si128((__m128i *)&*src2);
                                                                xmm2 = _mm_load_si128((__m128i *)&arg_10);
                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 392), xmm2);
                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 376), xmm1);
                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 360), xmm0);
                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a1));
                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a1 + 16));
                                                                a2 = src2 + 280;
                                                                _mm_storeu_si128((__m128i *)(a2 + 16), xmm1);
                                                                _mm_storeu_si128((__m128i *)a2, xmm0);
                                                                a2 = src2 + 40;
                                                                xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                                xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1), xmm0);
                                                                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1 + 16), xmm1);
                                                                xmm0 = _mm_load_si128((__m128i *)&arg_e0);
                                                                xmm1 = _mm_load_si128((__m128i *)&arg_f0);
                                                                xmm2 = _mm_load_si128((__m128i *)&arg_100);
                                                                xmm3 = _mm_load_si128((__m128i *)&arg_110);
                                                                _mm_store_si128((__m128i *)&arg_50, xmm0);
                                                                _mm_store_si128((__m128i *)&arg_60, xmm1);
                                                                _mm_store_si128((__m128i *)&arg_70, xmm2);
                                                                _mm_store_si128((__m128i *)&arg_80, xmm3);
                                                                xmm0 = _mm_load_si128((__m128i *)&arg_120);
                                                                _mm_store_si128((__m128i *)&arg_90, xmm0);
                                                                result = (__int64 *)arg_130;
                                                                arg_a0 = (__int64)result;
                                                                return arg_a0;
                                                            }
                                                            do {
                                                                a1 = (size_t *)arg_3d0;
                                                                result = (__int64 *)arg_160;
                                                            } while (a1 >= arg_3d2);
                                                            return (__int64)result;
                                                        }
                                                        v5 = (__int64)result;
                                                        v5 &= 7;
                                                        if ((v5 == 0)) {
                                                            a2 -= 2;
                                                            if (a2 < 7) {
                                                                return (__int64)a2;
                                                            }
                                                            do {
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                a2 = a1[122];
                                                                a1 = v_3d8[(__int64)a2];
                                                                result -= 8;
                                                            } while ((result != 0));
                                                            return (__int64)result;
                                                        }
                                                        for (i2 = 0; v5 != i2; ++i2) {
                                                            v7 = a1[122];
                                                            a1 = v_3d8[v7];
                                                        }
                                                        result -= i2;
                                                        return (__int64)result;
                                                    }
                                                    result = 0;
                                                    v12 = (__int64)i;
                                                    v7 = 0;
                                                }
                                                a2 = v2 + v8*8;
                                                a2 += 984;
                                                v5 = (__int64)result;
                                                v5 &= 7;
                                                if ((v5 == 0)) {
                                                    v5 = (__int64)result;
                                                    if (result >= 8) {
                                                        do {
                                                            result = *a2;
                                                            result = (__int64 *)arg_3d8;
                                                            result = (__int64 *)arg_3d8;
                                                            result = (__int64 *)arg_3d8;
                                                            result = (__int64 *)arg_3d8;
                                                            result = (__int64 *)arg_3d8;
                                                            result = (__int64 *)arg_3d8;
                                                            ptr = (struct Struct_1_t *)arg_3d8;
                                                            a2 = ptr + 984;
                                                            v5 -= 8;
                                                        } while ((v5 != 0));
                                                        v9 = 0;
                                                        return v9;
                                                    }
                                                    return v9;
                                                }
                                                for (i2 = 0; v5 != i2; ++i2) {
                                                    ptr = *a2;
                                                    a2 = ptr + 984;
                                                }
                                                v5 = (__int64)result;
                                                v5 -= i2;
                                                if (result < 8) {
                                                    return v5;
                                                }
                                                return v5;
                                            }
                                            do {
                                                v2 = ptr->field_160;
                                                if (v2 == 0) JUMPOUT(0x14003f013);
                                                ++result;
                                                a1 = ptr->field_3D0;
                                                ptr = (struct Struct_1_t *)v2;
                                            } while (a1 >= arg_3d2);
                                            return (__int64)ptr;
                                        }
                                        a1 = (size_t *)v8;
                                        ptr = (struct Struct_1_t *)result;
                                        a1 = (size_t *)((__int64)(__int64)a1 & 7);
                                        if ((a1 == 0)) {
                                            result = (__int64 *)v8;
                                            if (v8 < 8) {
                                                return (__int64)result;
                                            }
                                            do {
                                                a1 = ptr->field_3D8;
                                                a1 = a1[123];
                                                a1 = a1[123];
                                                a1 = a1[123];
                                                a1 = a1[123];
                                                a1 = a1[123];
                                                a1 = a1[123];
                                                ptr = a1[123];
                                                result -= 8;
                                            } while ((result != 0));
                                            return (__int64)result;
                                        }
                                        for (a2 = 0; a1 != a2; ++a2) {
                                            ptr = ptr->field_3D8;
                                        }
                                        result = (__int64 *)v8;
                                        result = (__int64 *)((__int64)result - (__int64)a2);
                                        if (v8 >= 8) {
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    a1 = ptr->field_3D2;
                                    if (v8 >= a1) {
                                        return (__int64)a1;
                                    }
                                    return (__int64)a1;
                                }
                                result = (__int64 *)arg_d0;
                                i = (__int64 *)v_20;
                                arg_18 = (__int64)result;
                                xmm0 = _mm_loadu_si128((__m128i *)&arg_c0);
                                _mm_storeu_si128((__m128i *)(i + 8), xmm0);
                                result = 1;
                                *i = result;
                                xmm6 = _mm_load_si128((__m128i *)&arg_170);
                                return _mm_cvtsi128_si64(xmm6);
                            }
                            i2 = &off_140114E50;
                            sub_1400F3600(i, v9, v9, i2);
                            return sub_14003F040();
                        }
                        i2 = &off_140114E68;
                        sub_1400F3600(0, v5, v9, i2);
                        return sub_14003F040();
                    }
                    i2 = &off_140114E80;
                    sub_1400F3600(1, 0, 0, i2);
                    return sub_14003F040();
                }
                return i2;
            }
        }
        return i2;
    }
    return (__int64)result;
}