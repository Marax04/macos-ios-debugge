// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2C50();
__int64 sub_1400F3326();
__int64 sub_1400F1570();
__int64 sub_1401071ED();

__int64 __fastcall sub_140106FA0(__int64 *a1) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 *v_0;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 *v5;
    __int64 i;
    __int64 v12;
    __int64 v10;
    __int64 v13;
    __m128i xmm0;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 *src;
    __int64 v11;
    __int64 v14;

    ptr = (struct Struct_1_t *)a1;
    v3 = *a1;
    result = v3 + v3;
    v5 = 4;
    if (result >= 5) v5 = result;
    i = arg_8;
    v_28 = 520;
    v_20 = 1;
    a1 = rsp + 48;
    sub_1400F2C50(a1, v3, i, v5);
    if (v_30 == 1) {
        a1 = (__int64 *)v_38;
        v3 = v_40;
        sub_1400F3326(a1, v3);
        result = a1[3];
        v_28 = result;
        ++result;
        if ((result == 0)) JUMPOUT(0x14010745d);
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
        if (result <= a1) JUMPOUT(0x1401071ba);
        ++i;
        if (i <= result) i = result;
        a1 = rsp + 56;
        sub_1400F1570(a1, 8, i);
        a1 = (__int64 *)v_38;
        result = v_40;
        if (a1 == 0) JUMPOUT(0x14010744c);
        v3 = v_48;
        v_30 = v3;
        v_20 = (__int64)ptr;
        v5 = ptr->field_0;
        ptr = (struct Struct_1_t *)v_28;
        if (ptr == 0) JUMPOUT(0x1401071ed);
        xmm0 = _mm_load_si128((__m128i *)v5);
        v13 = _mm_movemask_epi8(xmm0);
        v13 = ~v13;
        i = 0;
        v7 = 0xF1357AEA2E62A9C5;
        v8 = (__int64)ptr;
        v9 = (__int64)v5;
        do {
            v10 = __builtin_ctz(v13);
            v10 += i;
            v3 =  + v10*8;
            src = v5;
            src -= v3;
            v11 = *(src - 8);
            v11 *= v7;
            v11 = __ROL8__(v11, 26);
            v14 = v11;
            v14 &= result;
            xmm0 = _mm_loadu_si128((__m128i *)&*(a1 + v14));
            v3 = _mm_movemask_epi8(xmm0);
            if (v3 == 0) JUMPOUT(0x14010718e);
            v3 = __builtin_ctz(v3);
            v3 += v14;
            v3 &= result;
            if ((*(a1 + v3) - 0) >= 0) JUMPOUT(0x1401071ac);
            src = v13 - 1;
            src = (__int64 *)((__int64)(__int64)src & v13);
            --v8;
            v11 >>= 57;
            v13 = v3 - 16;
            v13 &= result;
            *(a1 + v3) = v11;
            *(a1 + v13 + 16) = v11;
            v10 = ~v10;
            v3 = ~v3;
            v13 = v5[v10];
            v_0[v3] = v13;
            v13 = (__int64)src;
        } while (v8 != 0);
        return sub_1401071ED();
    } else {
        result = v_38;
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(v5);
        return result;
    }
}