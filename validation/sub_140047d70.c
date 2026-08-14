// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char field_0; // offset 0
    char field_1; // offset 1
    int field_2; // offset 2
    char _pad_2[2];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 7 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[32];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3340();
__int64 sub_1400F37D0();
__int64 sub_14004F470();
__int64 sub_140054AA0();
__int64 sub_140048552();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;
extern __int64 off_14012D270;
extern __int64 off_14011D5D0;
extern __int64 off_14011D5E0;

__int64 __fastcall sub_140047D70(int *a1, int *a2) {
    __int64 rsp;
    int arg_160;
    int arg_270;
    int arg_272;
    int arg_58;
    int v_20;
    int v_2c0;
    int v_2d0;
    int v_2d8;
    int v_30;
    __int64 v_40;
    int v_410;
    int v_418;
    int v_420;
    int v_430;
    int v_448;
    int v_450;
    int v_458;
    int v_460;
    int v_470;
    int v_480;
    int v_488;
    int v_490;
    int v_4a8;
    int v_4c0;
    int v_4c8;
    int v_4d0;
    int v_4e0;
    int v_4f0;
    int v_4f8;
    int v_50;
    int v_508;
    int v_510;
    int v_518;
    int v_520;
    int v_530;
    int v_540;
    int v_548;
    int v_550;
    int v_568;
    int v_58;
    int v_580;
    int v_588;
    int v_590;
    int v_598;
    int v_5a0;
    int v_5a8;
    __int64 v_60;
    int v_68;
    __int64 v_70;
    int v_78;
    int v_80;
    int v_90;
    int v_b50;
    int v_b60;
    int v_b70;
    int v_b80;
    int v_b90;
    int v_ba0;
    int v_c8;
    int v_d0;
    int v_d8;
    int v_e0;
    int v_e8;
    __int64 *v_0;
    __int64 *v_278;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v10;
    __int64 v4;
    __int64 v13;
    __int64 result;
    __int64 v11;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v12;
    __int64 v5;
    __int64 v6;
    __m128i xmm2;
    __int64 v7;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    dst = *a2;
    v10 = *(dst + 626);
    sub_14002EDF0(0, 728);
    if (result != 0) {
        v4 = result;
        arg_160 = 0;
        v13 = ptr->field_10;
        result = *(dst + 626);
        v11 = v13;
        v11 = ~v11;
        v11 += result;
        arg_272 = v11;
        result =  + v13*2;
        result += v13;
        a1 = *(dst + result*8 + 376);
        v_30 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + result*8 + 360));
        _mm_store_si128((__m128i *)&v_20, xmm0);
        result = v13;
        result <<= 5;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + result));
        xmm1 = _mm_loadu_si128((__m128i *)(dst + result + 16));
        _mm_store_si128((__m128i *)&v_90, xmm1);
        _mm_store_si128((__m128i *)&v_80, xmm0);
        if (v11 < 12) {
            result = dst + 360;
            v12 = v13 + 1;
            a1 = v4 + 360;
            a2 = v12 + v12*2;
            a2 = result + (__int64)(__int64)a2*8;
            result =  + v11*8;
            v5 = result + result*2;
            sub_1400F27F0(a1, a2, v5);
            v12 <<= 5;
            v12 += (__int64)dst;
            v11 <<= 5;
            sub_1400F27F0(v4, v12, v11);
            *(dst + 626) = v13;
            xmm0 = _mm_load_si128((__m128i *)&v_20);
            _mm_store_si128((__m128i *)&v_40, xmm0);
            result = v_30;
            v_50 = result;
            xmm0 = _mm_load_si128((__m128i *)&v_80);
            xmm1 = _mm_load_si128((__m128i *)&v_90);
            _mm_storeu_si128((__m128i *)&v_68, xmm1);
            _mm_storeu_si128((__m128i *)&v_58, xmm0);
            v11 = arg_272;
            v5 = v11 + 1;
            if (v11 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, v5, 12, v6);
                sub_1400F3340(8, 728);
                v6 = &off_14011D898;
                sub_1400F3600(0, v11, 11, v6);
            } else {
                v10 -= v13;
                if (v10 == v5) {
                    a1 = (int *)v4;
                    a1 += 632;
                    a2 = dst + v13*8;
                    a2 += 640;
                    v5 <<= 3;
                    sub_1400F27F0(a1, a2, v5);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    v5 = v_278[(__int64)a2];
                    arg_160 = v4;
                    arg_270 = (int)a2;
                    while (a2 < v11) {
                    }
                    a1 = (int *)v_70;
                    ptr2->field_30 = a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_40);
                    xmm1 = _mm_load_si128((__m128i *)&v_50);
                    xmm2 = _mm_load_si128((__m128i *)&v_60);
                    _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm2);
                    _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)ptr2, xmm0);
                    ptr2->field_38 = dst;
                    ptr2->field_40 = result;
                    ptr2->field_48 = v4;
                    ptr2->field_50 = result;
                    return _mm_cvtsi128_si64(xmm2);
                }
            }
            a1 = &off_14011D858;
            v5 = &off_14011D880;
            sub_1400F37D0(a1, 40, v5);
            _mm_store_si128((__m128i *)&v_ba0, xmm11);
            _mm_store_si128((__m128i *)&v_b90, xmm10);
            _mm_store_si128((__m128i *)&v_b80, xmm9);
            _mm_store_si128((__m128i *)&v_b70, xmm8);
            _mm_store_si128((__m128i *)&v_b60, xmm7);
            _mm_store_si128((__m128i *)&v_b50, xmm6);
            v13 = v5;
            ptr = (struct Struct_1_t *)a2;
            v_410 = (int)a1;
            result = off_14012D270;
            a1 = __readgsqword(88);
            result = v_0[result];
            ptr2 = result + 72;
            if (arg_58 != 1) JUMPOUT(0x14004c491);
            result = ptr2->field_0;
            a1 = ptr2->field_8;
            a2 = result + 1;
            v5 = result + 2;
            *(__int64 *)ptr2 = (__int64)(v5);
            v_420 = 0;
            v_430 = 0;
            v_448 = 0;
            v_450 = 8;
            v_458 = 0;
            xmm1 = _mm_loadu_si128((__m128i *)&off_14011D5D0);
            _mm_storeu_si128((__m128i *)&v_460, xmm1);
            xmm2 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
            _mm_storeu_si128((__m128i *)&v_470, xmm2);
            v_480 = (int)a2;
            v_488 = (int)a1;
            v7 = 0x8000000000000003;
            v_490 = v7;
            v_4a8 = v7;
            v_4c0 = 0;
            v_4c8 = 0;
            v_5a0 = 0;
            v_4e0 = 0;
            v_4f0 = 1;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_4f8, xmm0);
            v_508 = 0;
            v_510 = 8;
            v_518 = 0;
            _mm_storeu_si128((__m128i *)&v_520, xmm1);
            _mm_storeu_si128((__m128i *)&v_530, xmm2);
            v_540 = result;
            v_548 = (int)a1;
            v_550 = v7;
            v_568 = v7;
            v_580 = 0;
            v_5a8 = 0;
            v_588 = 0;
            v_590 = 8;
            v_598 = 0;
            v_418 = 0;
            v_60 = (__int64)ptr;
            v_68 = v13;
            v_70 = (__int64)ptr;
            v_78 = v13;
            v_80 = 0;
            if (v13 != 0) {
                result = (ptr->field_0 != 239) ? 1 : 0;
                a1 = (v13 == 1) ? 1 : 0;
                a1 = (int *)((__int64)(__int64)a1 | result);
                if (!((a1 != 0))) {
                    result = (ptr->field_1 != 187) ? 1 : 0;
                    a1 = (v13 == 2) ? 1 : 0;
                    a1 = (int *)((__int64)(__int64)a1 | result);
                    if (!((a1 != 0))) {
                        result = (ptr->field_2 != 191) ? 1 : 0;
                        a1 = (v13 < 3) ? 1 : 0;
                        a1 = (int *)((__int64)(__int64)a1 | result);
                        if ((a1 == 0)) JUMPOUT(0x14004b920);
                    }
                }
            }
            _mm_storeu_si128((__m128i *)&v_e8, xmm0);
            v_d0 = 1;
            v_d8 = 0;
            v_e0 = 8;
            a1 = rsp + 208;
            sub_14004F470(a1, a2, v5);
            ptr2 = (struct Struct_2_t *)ptr;
            v4 = rsp + 0x420;
            v_2c0 = 0;
            v_2d0 = 0;
            v_2d8 = 0x920;
            a1 = rsp + 208;
            a2 = rsp + 704;
            v5 = rsp + 96;
            sub_140054AA0(a1, a2, v5);
            result = v_d0;
            v_40 = (__int64)ptr;
            v_c8 = v13;
            if (result != 3) JUMPOUT(0x1400482eb);
            if (v_418 != 0) JUMPOUT(0x14004c3c9);
            result = v_70;
            result -= v_60;
            if ((v_4c8 & 1) == 0) JUMPOUT(0x14004854f);
            ptr2 = (struct Struct_2_t *)v_4d0;
            return sub_140048552();
        }
        return (__int64)ptr2;
    }
    return result;
}