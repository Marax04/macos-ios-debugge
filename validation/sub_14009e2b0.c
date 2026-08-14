// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
    char _pad_28[16];
    __int64 field_40; // offset 64
    char _pad_40[64];
    __int64 field_88; // offset 136
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[128];
    __int64 field_90; // offset 144
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F3360();
__int64 sub_14009E770();
__int64 sub_14006B5E0();
__int64 sub_1400972B0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140108880;
extern __int64 off_140108890;

__int64 __fastcall sub_14009E2B0(size_t *a1, size_t a2, int *a3, __int64 *a4) {
    __int64 rsp;
    __int64 v_20;
    int v_28;
    __int64 v_30;
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
    __int64 v_40;
    int v_41;
    int v_42;
    int v_43;
    int v_44;
    int v_45;
    int v_46;
    int v_47;
    __int64 v_48;
    int v_49;
    int v_4a;
    int v_4b;
    int v_4c;
    int v_4d;
    int v_4e;
    int v_4f;
    __int64 v_50;
    int v_58;
    int v_c0;
    int v_c8;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v9;
    struct Struct_2_t *ptr2;
    __int64 v8;
    __int64 v5;
    __int64 v11;
    __int64 *result;
    struct Struct_3_t *ptr3;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v6;
    __int64 *src;

    ptr = (struct Struct_1_t *)a4;
    v7 = (__int64)a3;
    v9 = a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(8, a4);
    if (result == 0) {
        sub_1400F3326(1, ptr);
        ptr2 = (struct Struct_2_t *)a1;
        v8 = ptr->field_10;
        v5 = ptr->field_28;
        v11 = v8 * 56;
        a1 = ptr->field_40;
        result = ptr->field_88;
        v9 = v5 + a1;
        v9 += (__int64)result;
        v9 += v11;
        v9 += 136;
        if (!((v9 >= 0))) {
            sub_1400F3360(a1);
        }
        ptr3 = (struct Struct_3_t *)a2;
        v_48 = (__int64)a1;
        v_50 = (__int64)result;
        if ((0 /* unresolved: flags == */)) JUMPOUT(0x14009e934);
        sub_14002EDF0(0, v9);
        if (result == 0) JUMPOUT(0x14009eb4c);
        v_28 = v9;
        v_30 = (__int64)result;
        v_38 = 0;
        if (v9 <= 7) JUMPOUT(0x14009e94f);
        v9 = 0;
        a1 = 0x3430343230464E49;
        *(result + v9) = a1;
        v9 += 8;
        v_38 = v9;
        result = (__int64 *)v_28;
        a1 = (size_t *)result;
        a1 -= v9;
        v_40 = (__int64)ptr2;
        if (a1 <= 3) JUMPOUT(0x14009e970);
        a1 = (size_t *)v_30;
        *(a1 + v9) = 4;
        v9 += 4;
        v_38 = v9;
        ptr2 = ptr3->field_90;
        a2 = (size_t)result;
        a2 -= v9;
        if (a2 <= 7) JUMPOUT(0x14009e992);
        *(a1 + v9) = ptr2;
        v9 += 8;
        v_38 = v9;
        ptr2 = ptr3 + 152;
        a2 = (size_t)result;
        a2 -= v9;
        if (a2 <= 31) JUMPOUT(0x14009e9b9);
        xmm0 = _mm_loadu_si128((__m128i *)ptr2);
        xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
        _mm_storeu_si128((__m128i *)(a1 + v9 + 16), xmm1);
        _mm_storeu_si128((__m128i *)(a1 + v9), xmm0);
        v9 += 32;
        v_38 = v9;
        ptr2 = 0xFFFFFFFF;
        if (v8 < ptr2) ptr2 = v8;
        result -= v9;
        if (result <= 3) JUMPOUT(0x14009e9e0);
        *(a1 + v9) = ptr2;
        v9 += 4;
        v_38 = v9;
        if (v8 == 0) JUMPOUT(0x14009e770);
        v6 = ptr3->field_8;
        v6 += 44;
        ptr2 = 0;
        a1 = rsp + 40;
        do {
            result = (__int64 *)v_28;
            a2 = (size_t)result;
            a2 -= v9;
            if (a2 <= 7) JUMPOUT(0x14009e6da);
            ptr = ptr2 + v6;
            a3 = (int *)v_30;
            a2 = *(__int64 *)(ptr - 12);
            *(a3 + v9) = a2;
            v9 += 8;
            v_38 = v9;
            src = *(__int64 *)(ptr - 4);
            a2 = (size_t)result;
            a2 -= v9;
            if (a2 <= 3) JUMPOUT(0x14009e6fd);
            *(a3 + v9) = src;
            v9 += 4;
            v_38 = v9;
            a2 = (size_t)result;
            a2 -= v9;
            if (a2 <= 11) JUMPOUT(0x14009e725);
            a2 = ptr->field_8;
            *(a3 + v9 + 8) = a2;
            a2 = ptr->field_0;
            *(a3 + v9) = a2;
            v9 += 12;
            v_38 = v9;
            result -= v9;
            if (result <= 31) JUMPOUT(0x14009e74d);
            result = ptr2 + v6;
            result -= 44;
            xmm0 = _mm_loadu_si128((__m128i *)result);
            xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
            _mm_storeu_si128((__m128i *)(a3 + v9 + 16), xmm1);
            _mm_storeu_si128((__m128i *)(a3 + v9), xmm0);
            v9 += 32;
            v_38 = v9;
            ptr2 += 56;
        } while (v11 != ptr2);
        return sub_14009E770();
    } else {
        ptr3 = (struct Struct_3_t *)result;
        v11 = v_c8;
        src = (__int64 *)v_c0;
        a1 = 0x9E3779B97F4A7C15;
        a1 = (size_t *)((__int64)(__int64)(__int64)a1 * v7);
        a2 = 0xDEADBEEFCAFEBABE;
        result = 0x3E08D64756AEB12B;
        result = (__int64 *)((__int64)result + (__int64)a1);
        xmm0 = _mm_cvtsi64_si128(a1);
        a1 = (size_t *)((__int64)(__int64)a1 ^ a2);
        result = (__int64 *)((__int64)(__int64)result ^ a2);
        a2 = 0x94D04955442792AD;
        a2 *= v7;
        a3 = 0x6A09E667BB67AE85;
        a3 = (int *)((__int64)(__int64)a3 ^ a2);
        a2 = v7 * 0xFE94F82B;
        a2 ^= 0x5F1D36F1;
        v_30 = (__int64)a1;
        xmm0 = _mm_shuffle_epi32(xmm0, 68);
        xmm0 = _mm_add_epi64(xmm0, _mm_load_si128((__m128i *)&off_140108880));
        xmm0 = _mm_xor_si128(xmm0, _mm_load_si128((__m128i *)&off_140108890));
        _mm_storeu_si128((__m128i *)&v_38, xmm0);
        v_48 = (__int64)result;
        v_50 = (__int64)a3;
        v_58 = a2;
        a1 = rsp + 48;
        a2 = rsp + 80;
        sub_14006B5E0(a1, a2, ptr3, ptr);
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
        v_48 = 0;
        v_49 = 0;
        v_4a = 0;
        v_4b = 0;
        v_4c = 0;
        v_4d = 0;
        v_4e = 0;
        v_4f = 0;
        v11 &= 0xDFFFFFFF;
        v_28 = v11;
        v_20 = (__int64)ptr;
        sub_1400972B0(v9, src, 8, ptr3);
        if (((__int64)result & 1) == 0) {
            result = *src;
            ptr2->field_1 = result;
            ptr = 0;
        } else {
            a1 = (size_t *)result;
            a1 = (size_t *)((__int64)(__int64)a1 >> 32);
            result = (__int64 *)((__int64)(__int64)result >> 16);
            ptr2->field_2 = result;
            ptr2->field_4 = a1;
            ptr = 1;
        }
        off_140108030(a1);
        off_140108038(result, 0, ptr3);
        *(__int64 *)ptr2 = (__int64)(ptr);
        return (__int64)result;
    }
}