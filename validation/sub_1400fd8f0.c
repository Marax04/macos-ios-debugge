// inferred from 21 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    char field_3; // offset 3
    char field_4; // offset 4
    char field_5; // offset 5
    char field_6; // offset 6
    char field_7; // offset 7
    __int16 field_8; // offset 8
    char _pad_8[1];
    int field_B; // offset 11
    char _pad_B[1];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int16 field_28; // offset 40
    int field_2A; // offset 42
    char _pad_2A[2];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[8];
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int16 field_58; // offset 88
    int field_5A; // offset 90
    char _pad_5A[2];
    __int64 field_60; // offset 96
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[48];
    __int64 field_60; // offset 96
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F87E0();
__int64 sub_1400F8980();
__int64 sub_1400F8910();
__int64 sub_1400F3510();
__int64 sub_1400FDE9C();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400FD8F0(int *a1) {
    __int64 rsp;
    int arg_3;
    int arg_4;
    int arg_8;
    int arg_9;
    int v_100;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    __int64 v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_94;
    int v_98;
    __int64 v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_c8;
    int v_d0;
    int v_d8;
    int v_e8;
    int v_f0;
    int v_f8;
    struct Struct_2_t *ptr;
    __m128i xmm6;
    struct Struct_1_t *result;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v2;
    __int64 v5;
    int v6;

    _mm_store_si128((__m128i *)&v_100, xmm6);
    ptr = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 12);
    if (result == 0) {
        sub_1400F3326(1, 12);
    } else {
        a1 = 0x2D61726F6870797A;
        *(__int64 *)result = (__int64)(a1);
        result->field_8 = 0x6F6D6564;
        v_98 = 12;
        v_a0 = (__int64)result;
        v_a8 = 12;
        v_b0 = 0;
        v_b8 = 8;
        xmm6 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_c0, xmm6);
        v_d0 = 8;
        _mm_storeu_si128((__m128i *)&v_d8, xmm6);
        v_e8 = 8;
        v_f0 = 0;
        v_f8 = 1;
        sub_14002EDF0(0, 7);
        if (result != 0) {
            result->field_3 = 0x65747570;
            *(__int64 *)result = (__int64)(0x706D6F63);
            v_48 = 7;
            v_50 = (__int64)result;
            v_58 = 7;
            v_90 = 0;
            v_60 = 0;
            v_68 = 8;
            _mm_storeu_si128((__m128i *)&v_70, xmm6);
            v_80 = 4;
            v_88 = 0;
            v_94 = 0xF08;
            v_40 = 0;
            v_28 = 0;
            v_30 = 8;
            v_38 = 0;
            a1 = rsp + 40;
            sub_1400F87E0(a1);
            a1 = (int *)v_28;
            result = (struct Struct_1_t *)v_30;
            src = 0x8000000000000001;
            *(__int64 *)result = (__int64)(src);
            result->field_8 = 1;
            result->field_10 = 3;
            result->field_18 = 1;
            result->field_20 = 7;
            result->field_28 = 512;
            result->field_2A = 8;
            v_38 = 1;
            if (a1 == 1) {
                a1 = rsp + 40;
                sub_1400F87E0(a1);
                a1 = (int *)v_28;
                result = (struct Struct_1_t *)v_30;
            }
            result->field_30 = src;
            result->field_38 = 0;
            result->field_48 = 1;
            result->field_50 = 256;
            result->field_58 = 0;
            result->field_5A = 8;
            v_38 = 2;
            if (a1 == 2) {
                a1 = rsp + 40;
                sub_1400F87E0(a1);
                result = (struct Struct_1_t *)v_30;
            }
            a1 = 0x8000000000000009;
            result->field_60 = a1;
            v_38 = 3;
            a1 = rsp + 96;
            sub_1400F8980(a1);
            result = (struct Struct_1_t *)v_68;
            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
            xmm1 = _mm_loadu_si128((__m128i *)&v_38);
            _mm_storeu_si128((__m128i *)(result + 16), xmm1);
            _mm_storeu_si128((__m128i *)result, xmm0);
            v_70 = 1;
            a1 = rsp + 176;
            sub_1400F8910(a1);
            result = (struct Struct_1_t *)v_b8;
            xmm0 = _mm_loadu_si128((__m128i *)&v_88);
            _mm_storeu_si128((__m128i *)(result + 64), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_48);
            xmm1 = _mm_loadu_si128((__m128i *)&v_58);
            xmm2 = _mm_loadu_si128((__m128i *)&v_68);
            xmm3 = _mm_loadu_si128((__m128i *)&v_78);
            _mm_storeu_si128((__m128i *)(result + 48), xmm3);
            _mm_storeu_si128((__m128i *)(result + 32), xmm2);
            _mm_storeu_si128((__m128i *)(result + 16), xmm1);
            _mm_storeu_si128((__m128i *)result, xmm0);
            v_c0 = 1;
            result = (struct Struct_1_t *)v_f8;
            ptr->field_60 = result;
            xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
            _mm_storeu_si128((__m128i *)(ptr + 80), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_98);
            xmm1 = _mm_loadu_si128((__m128i *)&v_a8);
            xmm2 = _mm_loadu_si128((__m128i *)&v_c8);
            xmm3 = _mm_loadu_si128((__m128i *)&v_d8);
            _mm_storeu_si128((__m128i *)(ptr + 64), xmm3);
            _mm_storeu_si128((__m128i *)(ptr + 48), xmm2);
            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
            _mm_storeu_si128((__m128i *)ptr, xmm0);
            result = (struct Struct_1_t *)v_b8;
            ptr->field_20 = result;
            result = (struct Struct_1_t *)v_c0;
            ptr->field_28 = result;
            xmm6 = _mm_load_si128((__m128i *)&v_100);
            return (__int64)result;
        }
    }
    sub_1400F3326(1, 7);
    ptr = (struct Struct_2_t *)a1;
    v_28 = 0;
    v_30 = 1;
    v_38 = 0;
    a1 = rsp + 40;
    sub_1400F3510(a1);
    result = (struct Struct_1_t *)v_30;
    *(__int64 *)result = (__int64)(83);
    v_38 = 1;
    if (v_28 == 1) JUMPOUT(0x140100934);
    result = (struct Struct_1_t *)v_30;
    result->field_1 = 85;
    v_38 = 2;
    if (v_28 == 2) JUMPOUT(0x140100943);
    result = (struct Struct_1_t *)v_30;
    result->field_2 = 86;
    v_38 = 3;
    if (v_28 == 3) JUMPOUT(0x140100952);
    result = (struct Struct_1_t *)v_30;
    result->field_3 = 87;
    v_38 = 4;
    if (v_28 == 4) JUMPOUT(0x140100961);
    result = (struct Struct_1_t *)v_30;
    result->field_4 = 65;
    v_38 = 5;
    if (v_28 == 5) JUMPOUT(0x140100970);
    result = (struct Struct_1_t *)v_30;
    result->field_5 = 84;
    v_38 = 6;
    if (v_28 == 6) JUMPOUT(0x14010097f);
    result = (struct Struct_1_t *)v_30;
    result->field_6 = 65;
    v_38 = 7;
    if (v_28 == 7) JUMPOUT(0x14010098e);
    result = (struct Struct_1_t *)v_30;
    result->field_7 = 85;
    v_38 = 8;
    result = (struct Struct_1_t *)v_28;
    if (result == 8) JUMPOUT(0x14010099d);
    a1 = (int *)v_30;
    arg_8 = 65;
    v_38 = 9;
    if (result == 9) JUMPOUT(0x1401009b1);
    a1 = (int *)v_30;
    arg_9 = 86;
    v_38 = 10;
    if (result == 10) JUMPOUT(0x1401009c5);
    a1 = (int *)v_30;
    a1[1] = 65;
    v_38 = 11;
    if (result == 11) JUMPOUT(0x1401009d9);
    result = (struct Struct_1_t *)v_30;
    result->field_B = 87;
    v_38 = 12;
    sub_14002EDF0(0, 7);
    if (result == 0) JUMPOUT(0x140101b23);
    src = (__int64 *)result;
    *(__int64 *)result = (__int64)(0x8148);
    result->field_3 = 296;
    result->field_2 = 236;
    result = (struct Struct_1_t *)v_28;
    v2 = v_38;
    result -= v2;
    if (result <= 6) JUMPOUT(0x140100ef2);
    result = (struct Struct_1_t *)v_30;
    a1 = *src;
    v5 = arg_3;
    *(__int64 *)(result + v2 + 3) = (__int64)(v5);
    *(__int64 *)(result + v2) = (__int64)(a1);
    v2 += 7;
    v_38 = v2;
    off_140108030(a1, v2, v5);
    ((__int64 (*)())off_140108038)(result, 0, src);
    sub_14002EDF0(0, 8);
    if (result == 0) JUMPOUT(0x140101b05);
    src = (__int64 *)result;
    *(__int64 *)result = (__int64)(0x248C8948);
    result = (struct Struct_1_t *)v_28;
    v2 = v_38;
    arg_4 = 288;
    result -= v2;
    v_60 = (__int64)ptr;
    if (result <= 7) JUMPOUT(0x140100f1b);
    result = (struct Struct_1_t *)v_30;
    a1 = *src;
    *(__int64 *)(result + v2) = (__int64)(a1);
    v2 += 8;
    v_38 = v2;
    off_140108030(a1, v2);
    ((__int64 (*)())off_140108038)(result, 0, src);
    src = rsp + 64;
    ptr = off_140108038;
    v6 = 0;
    return sub_1400FDE9C();
}