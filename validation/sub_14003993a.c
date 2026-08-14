// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8751424];
    __int64 field_858948; // offset 0x858948
};

__int64 sub_188039964();
__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400327E0();
__int64 sub_14003F430();
__int64 sub_140038250();
__int64 sub_140039CA1();
__int64 sub_1400F3360();
__int64 sub_14003D3A5();
extern __int64 off_1401137A0;

__int64 __fastcall sub_14003993A(__int64 a1, int a2, int a3, size_t a4) {
    int arg_510;
    int arg_518;
    int arg_520;
    int arg_528;
    int arg_529;
    int arg_52d;
    int arg_52f;
    int arg_548;
    int arg_576;
    int arg_577;
    __int64 v_11;
    __int64 v_13;
    __int64 v_17;
    __int64 v_18;
    int v_20;
    __int64 v_28;
    int v_30;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 *v6;
    __int64 v7;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v9;
    __int64 v8;
    __int64 v2;
    __int64 v10;

    *(__int64 *)(ptr - 72) = (__int64)(*(__int64 *)(ptr - 72) + a1);
    *(__int64 *)ptr = (__int64)(ptr->field_0 + ptr);
    *(__int64 *)ptr = (__int64)(ptr->field_0 + ptr);
    *(__int64 *)ptr = (__int64)(ptr->field_0 + ptr);
    ptr->field_858948 = ptr->field_858948 + ptr;
    ptr += 0;
    a1 += a1;
    sub_188039964(a1);
    if (v2 >= 0) {
        sub_14002EDF0(0, v2, a3, a4);
        if (ptr == 0) JUMPOUT(0x14003d380);
        v3 = (__int64)ptr;
        a2 = arg_548;
        sub_1400F27F0(ptr, a2, v2);
        arg_510 = v2;
        arg_518 = v3;
        arg_520 = v2;
        arg_528 = 0;
        v_20 = arg_520;
        ptr = (struct Struct_1_t *)arg_528;
        v_18 = (__int64)ptr;
        ptr = (struct Struct_1_t *)arg_529;
        v_17 = (__int64)ptr;
        ptr = (struct Struct_1_t *)arg_52d;
        v_13 = (__int64)ptr;
        ptr = (struct Struct_1_t *)arg_52f;
        v_11 = (__int64)ptr;
        v_30 = arg_510;
        v6 = (__int64 *)arg_518;
        v_28 = (__int64)v6;
        a2 = &off_1401137A0;
        v7 = v10 - 48;
        sub_1400327E0(v7, a2, 4);
        xmm0 = _mm_load_si128((__m128i *)&v_30);
        xmm1 = _mm_load_si128((__m128i *)&v_20);
        _mm_store_si128((__m128i *)&arg_520, xmm1);
        _mm_store_si128((__m128i *)&arg_510, xmm0);
        v3 = arg_518;
        v9 = arg_520;
        arg_576 = 1;
        v8 = v10 - 48;
        sub_14003F430(v8, v3);
        ptr = 0;
        if (!__OFSUB(v6, v_30)) JUMPOUT(0x140039b78);
        arg_576 = 1;
        sub_140038250(v3, v9);
        if (v6 == 0) JUMPOUT(0x140039d24);
        if (a2 != 2) JUMPOUT(0x140039c41);
        if (*v6 != 0x2E2E) JUMPOUT(0x140039c41);
        a2 = 2;
        return sub_140039CA1();
    } else {
        arg_577 = 1;
        sub_1400F3360();
        return sub_14003D3A5();
    }
}