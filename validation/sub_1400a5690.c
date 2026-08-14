// inferred from 12 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    char _pad_48[40];
    char field_78; // offset 120
    char field_79; // offset 121
    __int64 field_7A; // offset 122
    char _pad_7A[4];
    __int64 field_86; // offset 134
};

__int64 sub_1400F1D90();
__int64 sub_140034600();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_1400A5C93();
__int64 sub_1400F3360();
extern __int64 off_14011AB10;
extern __int64 off_14011AB70;
extern __int64 off_14011ABC8;
extern __int64 off_14011AC18;
extern __int64 off_14011AC70;
extern __int64 off_14011ACC0;
extern __int64 off_14011AD08;
extern __int64 off_14011AD50;
extern __int64 off_14011ADA8;
extern __int64 off_14011ADF8;
extern __int64 off_14011AE40;
extern __int64 off_14011AE98;
extern __int64 off_14011AED8;

__int64 __fastcall sub_1400A5690(int a1, __int64 a2, __int64 *a3) {
    __int64 rsp;
    int v_1240;
    int v_1250;
    int v_1260;
    int v_1270;
    int v_1280;
    int v_1290;
    int v_140;
    int v_2f8;
    int v_5f0;
    int v_5f8;
    int v_600;
    int v_608;
    int v_68;
    int v_70;
    int v_d8;
    int v_e0;
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v4;
    __int64 v3;
    __m128i xmm6;
    __int64 result;
    __int64 v7;
    __int64 v9;
    __int64 v8;
    __int64 v5;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;

    sub_1400F1D90(0x12A8);
    _mm_store_si128((__m128i *)&v_1290, xmm11);
    _mm_store_si128((__m128i *)&v_1280, xmm10);
    _mm_store_si128((__m128i *)&v_1270, xmm9);
    _mm_store_si128((__m128i *)&v_1260, xmm8);
    _mm_store_si128((__m128i *)&v_1250, xmm7);
    _mm_store_si128((__m128i *)&v_1240, xmm6);
    ptr = (struct Struct_1_t *)a3;
    v6 = a2;
    v4 = a1;
    if (a3[16] == 0) {
        v3 = &off_14011AB10;
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        xmm6 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AB70;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011ABC8;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AC18;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AC70;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011ACC0;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AD08;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AD50;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011ADA8;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011ADF8;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AE40;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AE98;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        result = &off_14011AED8;
        v_5f0 = result;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
        v_5f0 = v3;
        v_5f8 = 1;
        v_600 = 8;
        _mm_storeu_si128((__m128i *)&v_608, xmm6);
        a1 = rsp + 0x5F0;
        sub_140034600(a1);
    }
    v7 = ptr->field_10;
    if (v7 >= 0) {
        v9 = ptr->field_7A;
        result = ptr->field_86;
        v_140 = result;
        xmm6 = _mm_loadu_si128((__m128i *)(ptr + 96));
        v3 = ptr->field_8;
        if (v7 != 0) {
            sub_14002EDF0(0, v7);
            v8 = result;
            if (result == 0) {
                sub_1400F3326(1, v7);
                v8 = 1;
            }
            sub_1400F27F0(v8, v3, v7);
            v5 = ptr->field_28;
            if (v5 >= 0) {
                v_2f8 = v6;
                v3 = ptr->field_20;
                v_e0 = v4;
                v_70 = v9;
                if ((0 /* unresolved: flags == */)) {
                    v6 = 1;
                    sub_1400F27F0(v6, v3, v5);
                    v9 = 0x8000000000000000;
                    result = 0;
                    if (!__OFSUB(result, ptr->field_30)) {
                        v3 = ptr->field_40;
                        v4 = ptr->field_38;
                        if (v3 != 0) {
                            sub_14002EDF0(0, v3);
                            if (result == 0) {
                                sub_1400F3326(1, v3);
                                result = 1;
                            }
                            v_d8 = result;
                            sub_1400F27F0(result, v4, v3);
                            v4 = ptr->field_78;
                            a1 = ptr->field_79;
                            result = 0;
                            if (!__OFSUB(result, ptr->field_48)) JUMPOUT(0x1400a5c38);
                            v_68 = a1;
                            return sub_1400A5C93();
                        }
                        return v_68;
                    }
                    v3 = v9;
                    return v3;
                }
                sub_14002EDF0(0, v5);
                v6 = result;
                if (result != 0) {
                    return v6;
                }
                sub_1400F3326(1, v5);
                return v6;
            }
            do {
                sub_1400F3360();
                return v6;
            } while (v3 < 0);
            return v6;
        }
        return v6;
    }
    return result;
}