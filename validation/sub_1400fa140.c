// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_14007BF40();
__int64 sub_1400FA38C();

__int64 __fastcall sub_1400FA140(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int *v_0;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 *src;
    __int64 i;
    __int64 v12;
    __int64 v10;
    __int64 v13;
    __m128i xmm0;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 *src2;
    __int64 v11;
    __int64 v14;

    ptr = (struct Struct_1_t *)a1;
    v3 = *a1;
    result = v3 + v3;
    src = 4;
    if (result >= 5) src = result;
    i = arg_8;
    v_28 = 152;
    v_20 = 8;
    a1 = rsp + 48;
    sub_1400F2C50(a1, v3, i, src);
    if (v_30 == 1) {
        a1 = (__int64 *)v_38;
        v3 = v_40;
        sub_1400F3326(a1, v3);
        result = a1[3];
        v_28 = result;
        v3 += result;
        if ((v3 < 0)) JUMPOUT(0x1400fa5fd);
        ptr = (struct Struct_1_t *)a1;
        v12 = arg_8;
        v10 = v12 + 1;
        result = v10;
        result >>= 3;
        v13 = v10;
        v13 &= -8;
        v13 -= result;
        i = v13;
        if (v12 < 8) v13 = v12;
        result = v13;
        result >>= 1;
        if (v3 <= result) JUMPOUT(0x1400fa359);
        ++i;
        if (i <= v3) i = v3;
        a1 = rsp + 56;
        sub_14007BF40(a1, 4, i);
        a1 = (__int64 *)v_38;
        result = v_40;
        if (a1 == 0) JUMPOUT(0x1400fa5ec);
        v3 = v_48;
        v_30 = v3;
        v_20 = (__int64)ptr;
        src = ptr->field_0;
        ptr = (struct Struct_1_t *)v_28;
        if (ptr == 0) JUMPOUT(0x1400fa38c);
        xmm0 = _mm_load_si128((__m128i *)src);
        v13 = _mm_movemask_epi8(xmm0);
        v13 = ~v13;
        i = 0;
        v7 = 0xF1357AEA2E62A9C5;
        v8 = (__int64)ptr;
        v9 = (__int64)src;
        do {
            v10 = __builtin_ctz(v13);
            v10 += i;
            v3 =  + v10*4;
            src2 = src;
            src2 -= v3;
            v11 = *(src2 - 4);
            v11 *= v7;
            v11 = __ROL8__(v11, 26);
            v14 = v11;
            v14 &= result;
            xmm0 = _mm_loadu_si128((__m128i *)&*(a1 + v14));
            v3 = _mm_movemask_epi8(xmm0);
            if (v3 == 0) JUMPOUT(0x1400fa32d);
            v3 = __builtin_ctz(v3);
            v3 += v14;
            v3 &= result;
            if ((*(a1 + v3) - 0) >= 0) JUMPOUT(0x1400fa34b);
            src2 = v13 - 1;
            src2 = (__int64 *)((__int64)(__int64)src2 & v13);
            --v8;
            v11 >>= 57;
            v13 = v3 - 16;
            v13 &= result;
            *(a1 + v3) = v11;
            *(a1 + v13 + 16) = v11;
            v10 = ~v10;
            v3 = ~v3;
            v14 = *(src + v10*4);
            v_0[v3] = v14;
            v13 = (__int64)src2;
        } while (v8 != 0);
        return sub_1400FA38C();
    } else {
        result = v_38;
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(src);
        return result;
    }
}