// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

// inferred from 12 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[32];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    int field_0; // offset 0
    char _pad_0[1];
    char field_5; // offset 5
    __int64 field_6; // offset 6
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F35E0();
__int64 sub_14008AB40();
__int64 sub_14001F3F0();
__int64 sub_14008BDC0();
__int64 sub_14008C400();
__int64 sub_14001F160();
__int64 off_140108268();
extern __int64 off_140118F90;
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14012D270;
extern __int64 off_14012D268;

__int64 __fastcall sub_14008C520(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    int v_100;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_50;
    __int64 v_60;
    int v_68;
    __int64 v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    __int64 v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    __int64 *v_0;
    struct Struct_2_t *ptr;
    __int64 *src;
    struct Struct_1_t *result;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v7;
    __m128i xmm6;
    __int64 v2;
    struct Struct_3_t *ptr2;
    struct Struct_4_t *ptr3;
    __int64 v11;
    __int64 v12;
    __int64 v9;
    __int64 v10;
    __m128i xmm2;
    __m128i xmm3;
    __m128i xmm4;

    _mm_store_si128((__m128i *)&v_a0, xmm6);
    ptr = (struct Struct_2_t *)a1;
    src = *a1;
    a1 = (__int64 *)arg_8;
    result = ptr->field_10;
    *(__int64 *)ptr = (__int64)(0);
    if (src == 0) {
        a1 = &off_140118F90;
        sub_1400F35E0(a1, src);
    } else {
        v6 = ptr->field_38;
        v_98 = v6;
        xmm0 = _mm_loadu_si128((__m128i *)(ptr + 24));
        xmm1 = _mm_loadu_si128((__m128i *)(ptr + 40));
        _mm_storeu_si128((__m128i *)&v_88, xmm1);
        _mm_storeu_si128((__m128i *)&v_78, xmm0);
        v_60 = (__int64)src;
        v_68 = (int)a1;
        v_70 = (__int64)result;
        xmm0 = _mm_loadu_si128((__m128i *)&v_78);
        v6 = rsp + 136;
        src = *src;
        src -= *a1;
        v7 = result->field_0;
        result = result->field_8;
        v_38 = v6;
        _mm_storeu_si128((__m128i *)&v_28, xmm0);
        v_20 = (__int64)result;
        a1 = rsp + 64;
        sub_14008AB40(a1, src, 1, v7);
        xmm6 = _mm_load_si128((__m128i *)&v_40);
        v2 = v_50;
        result = ptr->field_40;
        if (result != 0) {
            if (result != 1) {
                ptr2 = ptr->field_48;
                ptr3 = ptr->field_50;
                result = ptr3->field_0;
                if (result != 0) {
                    ((__int64 (*)())result)(ptr2);
                }
                if (ptr3->field_8 != 0) {
                    if (ptr3->field_10 >= 17) {
                        ptr2 = *(__int64 *)(ptr2 - 8);
                    }
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, ptr2);
                }
            } else {
                v11 = ptr->field_58;
                if (v11 != 0) {
                    v12 = ptr->field_48;
                    v12 += 24;
                    v9 = off_140108030;
                    v10 = off_140108038;
                    do {
                        v12 += 40;
                        --v11;
                    } while (!((v11 == 0)));
                }
            }
        }
        ptr->field_40 = 1;
        _mm_storeu_si128((__m128i *)(ptr + 72), xmm6);
        ptr->field_58 = v2;
        result = ptr->field_60;
        a1 = result->field_0;
        if (ptr->field_78 == 0) {
            src = ptr->field_70;
            result = 3;
            { __int64 __xchg_tmp = ptr->field_68; ptr->field_68 = result; result = __xchg_tmp; };
            if (result == 2) {
                a1 += 472;
                xmm6 = _mm_load_si128((__m128i *)&v_a0);
                return sub_14001F3F0();
            }
        } else {
            *a1 = *a1 + 1;
            if ((*a1 <= 0)) {
                _mm_store_si128((__m128i *)&v_100, xmm6);
                xmm0 = _mm_loadu_si128((__m128i *)(a1 + 8));
                arg_8 = 0;
                if ((arg_8 == 0)) JUMPOUT(0x14008c8ee);
                ptr = (struct Struct_2_t *)a1;
                result = a1[15];
                v_a0 = (__int64)result;
                xmm1 = _mm_loadu_si128((__m128i *)(a1 + 56));
                xmm2 = _mm_loadu_si128((__m128i *)(a1 + 72));
                xmm3 = _mm_loadu_si128((__m128i *)(a1 + 88));
                xmm4 = _mm_loadu_si128((__m128i *)(a1 + 104));
                _mm_store_si128((__m128i *)&v_90, xmm4);
                _mm_store_si128((__m128i *)&v_80, xmm3);
                _mm_store_si128((__m128i *)&v_70, xmm2);
                _mm_store_si128((__m128i *)&v_60, xmm1);
                _mm_store_si128((__m128i *)&v_30, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)(a1 + 24));
                xmm1 = _mm_loadu_si128((__m128i *)(a1 + 40));
                _mm_store_si128((__m128i *)&v_40, xmm0);
                _mm_store_si128((__m128i *)&v_50, xmm1);
                result = off_14012D270;
                a1 = __readgsqword(88);
                result = v_0[(__int64)result];
                v6 = result->field_18;
                if (v6 == 0) JUMPOUT(0x14008c8d6);
                a1 = rsp + 176;
                src = rsp + 48;
                v2 = 1;
                sub_14008BDC0(a1, src, v6, 1);
                xmm6 = _mm_load_si128((__m128i *)&v_b0);
                xmm0 = _mm_load_si128((__m128i *)&v_c0);
                xmm1 = _mm_load_si128((__m128i *)&v_d0);
                _mm_store_si128((__m128i *)&v_f0, xmm1);
                _mm_store_si128((__m128i *)&v_e0, xmm0);
                a1 = ptr + 128;
                _mm_store_si128((__m128i *)&v_30, xmm0);
                _mm_store_si128((__m128i *)&v_40, xmm1);
                sub_14008C400(a1);
                ptr->field_80 = 1;
                _mm_storeu_si128((__m128i *)(ptr + 136), xmm6);
                xmm0 = _mm_load_si128((__m128i *)&v_30);
                xmm1 = _mm_load_si128((__m128i *)&v_40);
                _mm_storeu_si128((__m128i *)(ptr + 152), xmm0);
                _mm_storeu_si128((__m128i *)(ptr + 168), xmm1);
                ptr2 = ptr->field_0;
                ptr = ptr2 + 4;
                result = 0;
                /* cmpxchg %v2, 4(%(__int64)ptr2) */;
                if ((0 /* unresolved: flags != */)) JUMPOUT(0x14008c8fa);
                result = off_14012D268;
                result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
                if (result != 0) JUMPOUT(0x14008c915);
                v2 = 0;
                result = ptr2->field_5;
                if (result != 0) JUMPOUT(0x14008c92b);
                ptr2->field_6 = 1;
                *(__int64 *)ptr2 = (__int64)(ptr2->field_0 + 1);
                off_140108268(ptr2);
                if (v2 == 0) {
                    result = off_14012D268;
                    result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
                    if (result != 0) JUMPOUT(0x14008c979);
                }
                result = 0;
                { __int64 __xchg_tmp = ptr->field_0; *(__int64 *)ptr = (__int64)(result); result = __xchg_tmp; };
                if (result == 2) JUMPOUT(0x14008c95d);
                xmm6 = _mm_load_si128((__m128i *)&v_100);
                return _mm_cvtsi128_si64(xmm6);
            } else {
                ptr2 = result->field_0;
                src = ptr->field_70;
                result = 3;
                { __int64 __xchg_tmp = ptr->field_68; ptr->field_68 = result; result = __xchg_tmp; };
                if (result == 2) {
                    a1 = ptr2 + 472;
                    sub_14001F3F0(a1, src);
                }
                *(__int64 *)ptr2 = (__int64)(ptr2->field_0 - 1);
                if (!((ptr2->field_0 != 0))) {
                    a1 = (__int64 *)ptr2;
                    xmm6 = _mm_load_si128((__m128i *)&v_a0);
                    return sub_14001F160();
                }
            }
        }
        xmm6 = _mm_load_si128((__m128i *)&v_a0);
        return _mm_cvtsi128_si64(xmm6);
    }
    return (__int64)result;
}