// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char field_10; // offset 16
    int field_11; // offset 17
    __int16 field_15; // offset 21
    char field_17; // offset 23
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_14005C86D();
__int64 sub_140063420();
__int64 sub_14005C854();
__int64 sub_14004F470();
__int64 sub_140054AA0();
__int64 sub_140063FC0();
__int64 sub_1400F27F0();
__int64 sub_140057260();
__int64 sub_1400575F0();
__int64 sub_14005EA92();
__int64 sub_14006002A();
__int64 sub_140056CD0();
__int64 sub_14005DB32();
__int64 sub_140060CA9();
__int64 sub_14002EDF0();
__int64 sub_14005C874();
__int64 off_140108038();
__int64 off_140108360();
extern __int64 off_14012216C;
extern __int64 off_14012D270;
extern __int64 off_14011D5D0;
extern __int64 off_14011D5E0;
extern __int64 off_140108030;
extern __int64 off_1401159D0;
extern __int64 off_140116670;

__int64 __fastcall sub_14005A9A0(size_t *a1, size_t *a2) {
    __int64 rsp;
    __int64 arg_10;
    __int64 arg_18;
    __int64 arg_20;
    int arg_58;
    __int64 arg_8;
    int arg_a8;
    int arg_a9;
    int v_18;
    __int64 v_1d0;
    int v_1e8;
    int v_1f8;
    int v_20;
    int v_200;
    int v_208;
    int v_230;
    __int64 v_240;
    __int64 v_258;
    __int64 v_270;
    __int64 v_28;
    int v_288;
    int v_2a0;
    int v_2b8;
    int v_2d0;
    int v_2d8;
    int v_2e0;
    int v_2e8;
    int v_2f0;
    int v_2f8;
    __int64 v_30;
    int v_378;
    __int64 v_38;
    __int64 v_40;
    int v_470;
    int v_478;
    int v_48;
    int v_488;
    int v_490;
    int v_498;
    int v_4a0;
    int v_50;
    int v_518;
    int v_520;
    int v_538;
    __int64 v_568;
    __int64 v_570;
    int v_5f8;
    int v_60;
    int v_610;
    int v_618;
    int v_620;
    int v_628;
    int v_638;
    int v_648;
    __int64 v_658;
    __int64 v_660;
    __int64 v_668;
    __int64 v_670;
    int v_68;
    __int64 v_688;
    int v_6a0;
    int v_6a1;
    __int64 v_70;
    int v_730;
    int v_738;
    int v_740;
    __int64 v_78;
    int v_7c0;
    int v_7c8;
    __int64 v_80;
    int v_88;
    __int64 v_9c0;
    int v_a70;
    int v_a80;
    int v_a90;
    int v_aa0;
    int v_ab0;
    int v_ac0;
    int v_ad0;
    int v_ae0;
    __int64 *v_0;
    __int64 *v_10;
    char *str;
    __int64 *v_8;
    struct Struct_1_t *ptr;
    __int64 *i;
    __m128i xmm0;
    __int64 *src;
    __int64 *i2;
    __int64 *result;
    __int64 *src2;
    __int64 i3;
    __int64 v6;
    __int64 v2;
    __m128i xmm6;
    __m128i xmm7;
    __m128i xmm8;
    __int64 *dst;
    __m128i xmm1;
    __m128i xmm13;
    __m128i xmm12;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;

    _mm_store_si128((__m128i *)&v_ae0, xmm13);
    _mm_store_si128((__m128i *)&v_ad0, xmm12);
    _mm_store_si128((__m128i *)&v_ac0, xmm11);
    _mm_store_si128((__m128i *)&v_ab0, xmm10);
    _mm_store_si128((__m128i *)&v_aa0, xmm9);
    _mm_store_si128((__m128i *)&v_a90, xmm8);
    _mm_store_si128((__m128i *)&v_a80, xmm7);
    _mm_store_si128((__m128i *)&v_a70, xmm6);
    ptr = (struct Struct_1_t *)a1;
    i = a2[3];
    if (i == 0) {
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
        ptr->field_8 = 1;
        ptr->field_10 = 0;
        ptr->field_17 = 0;
        ptr->field_15 = 0;
        ptr->field_11 = 0;
        ptr->field_18 = 8;
    } else {
        src = (__int64 *)a2;
        i2 = a2[2];
        result = *i2;
        a1 = result - 34;
        if (a1 <= 89) {
            a2 = &off_14012216C;
            switch ((__int64)a1) {
                default:
                    a1 = (size_t *)arg_20;
                    result = a1 + 1;
                    arg_20 = (__int64)result;
                    if (result < 80) {
                        if (*i2 != 123) {
                            a2 = (size_t *)src;
                            src = 1;
                            i = 8;
                            result = 0;
                            src2 = 0;
                            i3 = 0;
                            return sub_14005C86D();
                        } else {
                            ++i2;
                            --i;
                            arg_10 = (__int64)i2;
                            arg_18 = (__int64)i;
                            v_488 = 0;
                            v_490 = 8;
                            v_498 = 0;
                            a1 = rsp + 720;
                            sub_140063420(a1, src);
                            v_38 = (__int64)i2;
                            v_28 = (__int64)src;
                            if ((v_378 != 12)) JUMPOUT(0x14005db44);
                            v6 = v_2d0;
                            if (v6 != 1) {
                                i3 = v_2d8;
                                i = (__int64 *)v_2e0;
                                src2 = (__int64 *)v_2e8;
                                result = (__int64 *)v_2f0;
                                i2 = (__int64 *)v_2f8;
                                return sub_14005C854();
                            } else {
                                arg_10 = (__int64)i2;
                                i2 = i;
                                arg_18 = (__int64)i;
                                a1 = rsp + 720;
                                sub_14004F470(a1);
                                result = 8;
                                v_1d0 = (__int64)result;
                                v_470 = 0;
                                v2 = 0;
                                i = *src;
                                src2 = (__int64 *)arg_10;
                                v_488 = 0;
                                v_498 = 0;
                                v_4a0 = 0x920;
                                a1 = rsp + 480;
                                a2 = rsp + 0x488;
                                sub_140054AA0(a1, a2, src);
                                v6 = (__int64)str;
                                if (v6 != 3) JUMPOUT(0x14005c7f0);
                                src2 = (__int64 *)((__int64)src2 - (__int64)i);
                                i = (__int64 *)arg_10;
                                result = off_14012D270;
                                a1 = __readgsqword(88);
                                result = v_0[(__int64)result];
                                a1 = result + 72;
                                i -= *src;
                                v_478 = (int)a1;
                                if ((arg_58 != 1)) JUMPOUT(0x14006144b);
                                xmm0 = _mm_loadu_si128((__m128i *)a1);
                                result = _mm_cvtsi128_si64(xmm0);
                                ++result;
                                *a1 = result;
                                v_6a0 = 0;
                                result = 0x8000000000000003;
                                v_670 = (__int64)result;
                                v_688 = (__int64)result;
                                v_5f8 = 0;
                                a1 = rsp + 0x610;
                                v_610 = 0;
                                v_618 = 8;
                                v_620 = 0;
                                xmm6 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
                                _mm_storeu_si128((__m128i *)&v_628, xmm6);
                                xmm7 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
                                _mm_storeu_si128((__m128i *)&v_638, xmm7);
                                _mm_storeu_si128((__m128i *)&v_648, xmm0);
                                result = 0x8000000000000002;
                                v_658 = (__int64)result;
                                v_660 = (__int64)src2;
                                v_668 = (__int64)i;
                                sub_140063FC0(a1, v2);
                                result = v2 * 344;
                                src2 = (__int64 *)v_1d0;
                                result = (__int64 *)((__int64)result + (__int64)src2);
                                a1 = (size_t *)src2;
                                i = i2;
                                if (v2 == 0) JUMPOUT(0x14005ea92);
                                xmm8 = _mm_setzero_si128();
                                a2 = (size_t *)src2;
                                v_40 = (__int64)i;
                                v_568 = (__int64)result;
                                do {
                                    a1 = a2 + 344;
                                    v_538 = (int)a1;
                                    src2 = a2[21];
                                    if (src2 == 12) JUMPOUT(0x14005ea82);
                                    result = *a2;
                                    v_570 = (__int64)result;
                                    v6 = arg_8;
                                    i3 = a2[2];
                                    v2 = a2 + 176;
                                    a2 += 24;
                                    a1 = rsp + 0x880;
                                    sub_1400F27F0(a1, a2, 144);
                                    v_9c0 = (__int64)src2;
                                    a1 = rsp + 0x9C8;
                                    sub_1400F27F0(a1, v2, 168);
                                    v_2a0 = v6;
                                    if (i3 == 0) {
                                        i = rsp + 0x5F8;
                                        v2 = 0;
                                        if (v_6a1 == 0) {
                                            i += 24;
                                            src2 = rsp + 480;
                                            a2 = rsp + 0x880;
                                            sub_1400F27F0(src2, a2, 144);
                                            i2 = rsp + 0x488;
                                            sub_140057260(i2, i, src2);
                                            if (__OFSUB(v2, v_488)) JUMPOUT(0x14005f097);
                                            v2 = v_518;
                                            i = (__int64 *)v_520;
                                            a2 = rsp + 0x9C0;
                                            sub_1400F27F0(src2, a2, 176);
                                            sub_1400575F0(v2, i, i2, src2);
                                            i = (__int64 *)v_40;
                                            v6 = 0x8000000000000003;
                                            i2 = off_140108030;
                                            if (i3 == 0) {
                                                if (v_570 == 0) {
                                                    a1 = (size_t *)v_538;
                                                    a2 = a1;
                                                    result = (__int64 *)v_568;
                                                    a1 = (size_t *)result;
                                                    src2 = (__int64 *)v_1d0;
                                                    return sub_14005EA92();
                                                }
                                                ((__int64 (*)())i2)();
                                                dst = (__int64 *)v_2a0;
                                                off_140108038(result, 0, dst);
                                                return (__int64)dst;
                                            }
                                            result = (__int64 *)v_2a0;
                                            src2 = result + 128;
                                            do {
                                                result = (__int64 *)v_68;
                                                if (result == v6) {
                                                    result = (__int64 *)v_50;
                                                    if (result == v6) {
                                                        result = (__int64 *)v_38;
                                                        if (result == v6) {
                                                            result = (__int64 *)v_20;
                                                            if (result == v6) {
                                                                result = v_8;
                                                                if (result == v6) {
                                                                    src2 += 144;
                                                                    --i3;
                                                                    return i3;
                                                                }
                                                                if (result <= 0) {
                                                                    return i3;
                                                                }
                                                                v2 = *src2;
                                                                ((__int64 (*)())i2)();
                                                                off_140108038(result, 0, v2);
                                                                return v2;
                                                            }
                                                            if (result <= 0) {
                                                                return v2;
                                                            }
                                                            v2 = v_18;
                                                            ((__int64 (*)())i2)();
                                                            off_140108038(result, 0, v2);
                                                            return v2;
                                                        }
                                                        if (result <= 0) {
                                                            return v2;
                                                        }
                                                        v2 = v_30;
                                                        ((__int64 (*)())i2)();
                                                        off_140108038(result, 0, v2);
                                                        return v2;
                                                    }
                                                    if (result <= 0) {
                                                        return v2;
                                                    }
                                                    v2 = v_48;
                                                    ((__int64 (*)())i2)();
                                                    off_140108038(result, 0, v2);
                                                    return v2;
                                                }
                                                if (result <= 0) {
                                                    return v2;
                                                }
                                                v2 = v_60;
                                                ((__int64 (*)())i2)();
                                                off_140108038(result, 0, v2);
                                                return v2;
                                            } while (!((i3 == 0)));
                                            return v2;
                                        }
                                        return sub_14006002A();
                                    }
                                    v_2b8 = i3;
                                    result = (__int64 *)i3;
                                    result = (__int64 *)((__int64)(__int64)result << 4);
                                    result += (__int64)(__int64)result*8;
                                    v_30 = (__int64)result;
                                    i3 = 1;
                                    src2 = -144;
                                    i = rsp + 0x5F8;
                                    v2 = v6;
                                    do {
                                        i += 24;
                                        i2 = rsp + 480;
                                        sub_140056CD0(i2, v2);
                                        v6 = rsp + 0x910;
                                        i = 0;
                                        sub_140057260(v6, i, i2);
                                        a1 = rsp + 0x730;
                                        sub_1400F27F0(a1, v6, 160);
                                        if (__OFSUB(i, v_730)) {
                                            result = (__int64 *)v_738;
                                            a1 = (size_t *)v_740;
                                            a2 = (size_t *)arg_10;
                                            if (a1 >= a2) JUMPOUT(0x140061620);
                                            i = (__int64 *)arg_8;
                                            a1 = (size_t *)((__int64)(__int64)(__int64)a1 * 328);
                                            result = *(__int64 *)((__int64)i + (__int64)a1);
                                            if (result >= 8) JUMPOUT(0x14006095b);
                                            if (result >= 2) JUMPOUT(0x14005da3a);
                                            i = (__int64 *)((__int64)i + (__int64)a1);
                                            if (arg_a8 != 0) {
                                                v2 += 144;
                                                ++i3;
                                                result = (__int64 *)v_30;
                                                result = (__int64 *)((__int64)result + (__int64)src2);
                                                result -= 144;
                                                src2 -= 144;
                                                i3 = v_2b8;
                                                v2 = 0;
                                                if (arg_a9 != 1) JUMPOUT(0x14006028a);
                                                return v2;
                                            }
                                            return sub_14005DB32();
                                        }
                                        a1 = (size_t *)v_7c0;
                                        a2 = (size_t *)v_7c8;
                                        dst = (__int64 *)v_478;
                                        if (arg_10 != 1) {
                                            _mm_store_si128((__m128i *)&str, xmm8);
                                            i = (__int64 *)a2;
                                            i2 = (__int64 *)a1;
                                            a1 = rsp + 480;
                                            off_140108360(a1, 16);
                                            dst = (__int64 *)v_478;
                                            a2 = (size_t *)i;
                                            a1 = (size_t *)i2;
                                            result = (__int64 *)v_1e8;
                                            xmm0 = _mm_load_si128((__m128i *)&str);
                                            arg_8 = (__int64)result;
                                            arg_10 = 1;
                                            result = _mm_cvtsi128_si64(xmm0);
                                            ++result;
                                            *dst = result;
                                            str = 0;
                                            v_1f8 = 0;
                                            v_200 = 8;
                                            v_208 = 0;
                                            result = rsp + 528;
                                            _mm_storeu_si128((__m128i *)(result + 16), xmm7);
                                            _mm_storeu_si128((__m128i *)result, xmm6);
                                            _mm_storeu_si128((__m128i *)&v_230, xmm0);
                                            result = 0x8000000000000000;
                                            v_240 = (__int64)result;
                                            result = 0x8000000000000003;
                                            v_258 = (__int64)result;
                                            v_270 = (__int64)result;
                                            v_288 = 257;
                                            dst = rsp + 0x730;
                                            sub_1400575F0(a1, a2, dst, str);
                                            i = result;
                                            result = *result;
                                            if (result >= 8) JUMPOUT(0x140060c9d);
                                            if (result < 2) {
                                                return (__int64)result;
                                            }
                                            return sub_140060CA9();
                                        }
                                        xmm0 = _mm_loadu_si128((__m128i *)dst);
                                        return _mm_cvtsi128_si64(xmm0);
                                    } while (result != -144);
                                    return _mm_cvtsi128_si64(xmm0);
                                } while (a1 != result);
                                return _mm_cvtsi128_si64(xmm0);
                            }
                        }
                    } else {
                        sub_14002EDF0(0, 48);
                        if (result == 0) JUMPOUT(0x1400604ab);
                        a1 = 0x8000000000000002;
                        *result = a1;
                        src = 2;
                        i = 8;
                        i2 = &off_1401159D0;
                        src2 = 0;
                        i3 = 0;
                        v6 = 0;
                        return sub_14005C874();
                    }
                    break;
            }
        }
        result += 208;
        if (result >= 10) {
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
            src2 = ptr + 24;
            ptr->field_18 = 8;
            v2 = rsp + 120;
            result = ptr->field_18;
            a1 = ptr->field_20;
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 40));
            v_78 = (__int64)result;
            v_80 = (__int64)a1;
            _mm_storeu_si128((__m128i *)&v_88, xmm0);
            v_70 = 0;
            i = (__int64 *)v_80;
            if (i == 0) JUMPOUT(0x14005d885);
            result = 0;
            a1 = (size_t *)v_78;
            a2 = i + (__int64)(__int64)i*2;
            v_0[(__int64)a2] = 3;
            dst = &off_140116670;
            v_8[(__int64)a2] = dst;
            v_10[(__int64)a2] = 6;
            ++i;
            v_80 = (__int64)i;
            xmm0 = _mm_loadu_si128((__m128i *)v2);
            xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
            _mm_storeu_si128((__m128i *)(src2 + 16), xmm1);
            _mm_storeu_si128((__m128i *)src2, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)src2);
            xmm1 = _mm_loadu_si128((__m128i *)(src2 + 16));
            _mm_storeu_si128((__m128i *)&v_78, xmm0);
            _mm_storeu_si128((__m128i *)&v_88, xmm1);
            v_70 = (__int64)result;
            i = (__int64 *)v_80;
            if (i == result) JUMPOUT(0x14005d899);
            a1 = (size_t *)v_78;
            a2 = i + (__int64)(__int64)i*2;
            dst = 0x2200000000;
            v_0[(__int64)a2] = dst;
            ++i;
            v_80 = (__int64)i;
            xmm0 = _mm_loadu_si128((__m128i *)v2);
            xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
            _mm_storeu_si128((__m128i *)(src2 + 16), xmm1);
            _mm_storeu_si128((__m128i *)src2, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)src2);
            xmm1 = _mm_loadu_si128((__m128i *)(src2 + 16));
            _mm_storeu_si128((__m128i *)&v_78, xmm0);
            _mm_storeu_si128((__m128i *)&v_88, xmm1);
            v_70 = (__int64)result;
            i = (__int64 *)v_80;
            if (i == result) JUMPOUT(0x14005d8ad);
            a1 = (size_t *)v_78;
            a2 = i + (__int64)(__int64)i*2;
            dst = 0x2700000000;
            v_0[(__int64)a2] = dst;
            ++i;
            v_80 = (__int64)i;
            xmm0 = _mm_loadu_si128((__m128i *)v2);
            xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
            _mm_storeu_si128((__m128i *)(src2 + 16), xmm1);
            _mm_storeu_si128((__m128i *)src2, xmm0);
            ptr->field_8 = 1;
            return _mm_cvtsi128_si64(xmm1);
        } else {
            return _mm_cvtsi128_si64(xmm1);
        }
    }
    return (__int64)result;
}