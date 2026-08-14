// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_14007BF40();
__int64 sub_1400F9DEC();

__int64 __fastcall sub_1400F9B90(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    int v_20;
    __int64 v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 v5;
    __int64 i;
    __int64 v12;
    __int64 v10;
    __int64 v13;
    __m128i xmm0;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v11;
    __int64 v14;
    __int64 v2;

    ptr = (struct Struct_1_t *)a1;
    v3 = *a1;
    result = v3 + v3;
    v5 = 4;
    if (result >= 5) v5 = result;
    i = arg_8;
    v_28 = 48;
    v_20 = 8;
    a1 = rsp + 48;
    sub_1400F2C50(a1, v3, i, v5);
    if (v_30 == 1) {
        a1 = (__int64 *)v_38;
        v3 = v_40;
        sub_1400F3326(a1, v3);
        v5 = a1[3];
        result = v5;
        ++result;
        if ((result == 0)) JUMPOUT(0x1400fa07e);
        ptr = (struct Struct_1_t *)a1;
        v12 = arg_8;
        v10 = v12 + 1;
        a1 = (__int64 *)v10;
        a1 = (__int64 *)((__int64)(__int64)a1 >> 3);
        v13 = v10;
        v13 &= -8;
        v13 -= (__int64)a1;
        i = v13;
        if (v12 < 8) v13 = v12;
        a1 = (__int64 *)v13;
        a1 = (__int64 *)((__int64)(__int64)a1 >> 1);
        if (result <= a1) JUMPOUT(0x1400f9db4);
        ++i;
        if (i <= result) i = result;
        a1 = rsp + 56;
        sub_14007BF40(a1, 16, i);
        a1 = (__int64 *)v_38;
        result = v_40;
        if (a1 == 0) JUMPOUT(0x1400fa06d);
        v3 = v_48;
        v_30 = v3;
        v_28 = (__int64)ptr;
        v3 = v5;
        v5 = ptr->field_0;
        v_20 = v3;
        if (v3 == 0) JUMPOUT(0x1400f9dec);
        xmm0 = _mm_load_si128((__m128i *)v5);
        v10 = _mm_movemask_epi8(xmm0);
        v10 = ~v10;
        i = v5 - 16;
        v7 = 0;
        v8 = 0xF1357AEA2E62A9C5;
        v9 = v_20;
        v13 = v5;
        do {
            v11 = __builtin_ctz(v10);
            v11 += v7;
            v3 = v11;
            v3 <<= 4;
            ptr = (struct Struct_1_t *)i;
            ptr -= v3;
            v14 = ptr->field_0;
            v14 *= v8;
            v14 = __ROL8__(v14, 26);
            v3 = v14;
            v3 &= result;
            xmm0 = _mm_loadu_si128((__m128i *)(a1 + v3));
            ptr = _mm_movemask_epi8(xmm0);
            if (ptr == 0) JUMPOUT(0x1400f9d88);
            v2 = __builtin_ctz(ptr);
            v2 += v3;
            v2 &= result;
            if ((*(a1 + v2) - 0) >= 0) JUMPOUT(0x1400f9da6);
            v3 = v10 - 1;
            v3 &= v10;
            --v9;
            v14 >>= 57;
            ptr = v2 - 16;
            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & result);
            *(a1 + v2) = v14;
            *(__int64 *)((__int64)a1 + (__int64)ptr + 16) = v14;
            v11 = ~v11;
            v11 <<= 4;
            v2 = ~v2;
            v2 <<= 4;
            xmm0 = _mm_loadu_si128((__m128i *)(v5 + v11));
            _mm_storeu_si128((__m128i *)(a1 + v2), xmm0);
            v10 = v3;
        } while (v9 != 0);
        return sub_1400F9DEC();
    } else {
        result = v_38;
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(v5);
        return result;
    }
}