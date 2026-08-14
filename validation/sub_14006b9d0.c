// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14006C3D0();
__int64 sub_14006C500();
__int64 sub_14006BE0F();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();
__int64 sub_14006BD50();
__int64 sub_14006BFD0();
__int64 sub_1400F37D0();
__int64 sub_1400F3510();
__int64 off_140108030();
extern __int64 off_14011B7A0;
extern __int64 off_14011B7B0;
extern __int64 off_140117070;
extern __int64 off_140117220;
extern __int64 off_1401172B0;
extern __int64 off_140108038;

__int64 __fastcall sub_14006B9D0(int a1, int *a2, size_t a3, __int64 *str) {
    __int64 rsp;
    int v_100;
    int v_20;
    int v_210;
    int v_220;
    int v_230;
    int v_28;
    int v_29;
    int v_290;
    int v_2a;
    int v_2b;
    int v_2c;
    int v_2d;
    int v_2e;
    int v_2f;
    int v_30;
    int v_31;
    int v_32;
    int v_33;
    int v_34;
    int v_35;
    int v_36;
    int v_37;
    int v_38;
    int v_39;
    int v_3a;
    int v_3b;
    int v_3c;
    int v_3d;
    int v_3e;
    int v_3f;
    int v_40;
    int v_41;
    int v_42;
    int v_43;
    int v_44;
    int v_45;
    int v_46;
    int v_47;
    int v_48;
    int v_50;
    int v_58;
    int v_70;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    char *str2;
    __int64 v7;
    __int64 v8;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 *dst;
    __int64 i;
    __m128i xmm0;
    __m128i xmm1;
    __int64 result;
    __int64 v6;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    v7 = (__int64)str;
    v8 = a3;
    ptr = (struct Struct_1_t *)a2;
    v3 = a1;
    sub_14002EDF0(0, 72);
    if (result == 0) {
        sub_1400F3326(1, 72);
        _mm_store_si128((__m128i *)&v_230, xmm8);
        _mm_store_si128((__m128i *)&v_220, xmm7);
        _mm_store_si128((__m128i *)&v_210, xmm6);
        dst = str;
        v3 = a1;
        i = v_290;
        xmm0 = _mm_setzero_si128();
        _mm_store_si128((__m128i *)&v_50, xmm0);
        _mm_store_si128((__m128i *)&v_40, xmm0);
        _mm_store_si128((__m128i *)&v_30, xmm0);
        _mm_store_si128((__m128i *)&v_20, xmm0);
        if (a3 < 65) JUMPOUT(0x14006be05);
        _mm_store_si128((__m128i *)&v_d0, xmm0);
        _mm_store_si128((__m128i *)&v_c0, xmm0);
        _mm_store_si128((__m128i *)&v_b0, xmm0);
        _mm_store_si128((__m128i *)&str2, xmm0);
        xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7A0);
        _mm_store_si128((__m128i *)&v_e0, xmm1);
        xmm1 = _mm_loadu_si128((__m128i *)&off_14011B7B0);
        _mm_store_si128((__m128i *)&v_f0, xmm1);
        _mm_store_si128((__m128i *)&v_100, xmm0);
        sub_14006C3D0(str2);
        a1 = rsp + 32;
        sub_14006C500(a1, str2);
        return sub_14006BE0F();
    } else {
        dst = (__int64 *)result;
        v_48 = 72;
        v_50 = result;
        result = ptr->field_30;
        *dst = result;
        v_58 = 8;
        i = 8;
        result = 0;
        if (!__OFSUB(result, ptr->field_0)) {
            *(dst + 8) = 124;
            v_58 = 9;
            a2 = ptr->field_8;
            v6 = ptr->field_10;
            i = 9;
            if (v6 >= 64) {
                do {
                    a1 = rsp + 72;
                    dst = (__int64 *)a2;
                    sub_1400F5F90(a1, 9, v6);
                    a2 = (int *)dst;
                    dst = (__int64 *)v_50;
                    i = v_58;
                } while (true);
            }
            a1 = dst + i;
            sub_1400F27F0(a1, a2, v6);
            i += v6;
            v_58 = i;
            result = 0;
            if (__OFSUB(result, ptr->field_18)) {
                if (v7 == 0) {
                    xmm0 = _mm_setzero_si128();
                    _mm_store_si128((__m128i *)&v_70, xmm0);
                    _mm_store_si128((__m128i *)&str, xmm0);
                    v_20 = i;
                    a1 = rsp + 40;
                    a2 = rsp + 96;
                    sub_14006BD50(a1, a2, 32, dst);
                    xmm0 = _mm_setzero_si128();
                    _mm_store_si128((__m128i *)&v_70, xmm0);
                    _mm_store_si128((__m128i *)&str, xmm0);
                    v_20 = 32;
                    a2 = &off_140117070;
                    a1 = rsp + 40;
                    sub_14006BFD0(a1, a2, 21, str);
                    if (i < 0) {
                        a1 = &off_140117220;
                        a3 = &off_1401172B0;
                        sub_1400F37D0(a1, 51, a3);
                    }
                    if (i != 0) {
                        result = i;
                        result &= 7;
                        if (i >= 8) {
                            a1 = 0x7FFFFFFFFFFFFFF8;
                            i &= a1;
                            a1 = 0;
                            do {
                                *(dst + a1) = 0;
                                *(dst + a1 + 1) = 0;
                                *(dst + a1 + 2) = 0;
                                *(dst + a1 + 3) = 0;
                                *(dst + a1 + 4) = 0;
                                *(dst + a1 + 5) = 0;
                                *(dst + a1 + 6) = 0;
                                *(dst + a1 + 7) = 0;
                                a1 += 8;
                            } while (i != a1);
                        } else {
                            a1 = 0;
                        }
                        if (result != 0) {
                            dst += a1;
                            a1 = 0;
                            do {
                                *(dst + a1) = 0;
                                ++a1;
                            } while (result != a1);
                        }
                    }
                    v_28 = 0;
                    v_29 = 0;
                    v_2a = 0;
                    v_2b = 0;
                    v_2c = 0;
                    v_2d = 0;
                    v_2e = 0;
                    v_2f = 0;
                    v_30 = 0;
                    v_31 = 0;
                    v_32 = 0;
                    v_33 = 0;
                    v_34 = 0;
                    v_35 = 0;
                    v_36 = 0;
                    v_37 = 0;
                    v_38 = 0;
                    v_39 = 0;
                    v_3a = 0;
                    v_3b = 0;
                    v_3c = 0;
                    v_3d = 0;
                    v_3e = 0;
                    v_3f = 0;
                    v_40 = 0;
                    v_41 = 0;
                    v_42 = 0;
                    v_43 = 0;
                    v_44 = 0;
                    v_45 = 0;
                    v_46 = 0;
                    v_47 = 0;
                    xmm0 = _mm_load_si128((__m128i *)&str);
                    xmm1 = _mm_load_si128((__m128i *)&v_70);
                    _mm_storeu_si128((__m128i *)(v3 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)v3, xmm0);
                    if (v_48 != 0) {
                        v3 = v_50;
                        off_140108030(a1);
                        a1 = result;
                        JUMPOUT(off_140108038);
                    }
                    return a1;
                }
                v_20 = i;
                a1 = rsp + 40;
                a2 = (int *)v8;
                a3 = v7;
                return a3;
            }
            if (i == v_48) {
                a1 = rsp + 72;
                sub_1400F3510(a1, 0, v3);
                dst = (__int64 *)v_50;
            }
            *(dst + i) = 124;
            ++i;
            v_58 = i;
            a2 = ptr->field_20;
            ptr = ptr->field_28;
            result = v_48;
            result -= i;
            if (ptr > result) {
                a1 = rsp + 72;
                dst = (__int64 *)a2;
                sub_1400F5F90(a1, i, ptr);
                a2 = (int *)dst;
                i = v_58;
            }
            dst = (__int64 *)v_50;
            a1 = dst + i;
            sub_1400F27F0(a1, a2, ptr);
            i += (__int64)ptr;
            v_58 = i;
            if (v7 != 0) {
                return v_58;
            }
            return v_58;
        } else {
            result = 0;
            if (!__OFSUB(result, ptr->field_18)) {
                return result;
            }
            return result;
        }
        return result;
    }
}