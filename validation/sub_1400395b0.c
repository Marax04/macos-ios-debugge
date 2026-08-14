// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    char _pad_30[104];
    char field_A0; // offset 160
    __int64 field_A1; // offset 161
};

__int64 sub_14003E430();
__int64 sub_14002EDF0();
__int64 sub_14002F640();
__int64 sub_14003D132();
__int64 off_1401081D8();

__int64 __fastcall sub_1400395B0(__int64 a1, int a2, __int64 a3) {
    int arg_3d0;
    int arg_3d8;
    int arg_3e0;
    int arg_418;
    int arg_4a0;
    __int64 arg_4a8;
    int arg_4d0;
    int arg_4e0;
    __int64 arg_510;
    int arg_518;
    int arg_520;
    int arg_548;
    __int64 arg_550;
    __int64 arg_568;
    int arg_578;
    int arg_580;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int src;
    char *dst;
    struct Struct_1_t *ptr;
    __int64 i;
    __m128i xmm0;
    __int64 v7;
    __int64 *src2;
    __int64 v11;
    __int64 *dst2;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 v6;
    __int64 v5;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&arg_580, xmm6);
    arg_578 = -2;
    arg_418 = a3;
    ptr = (struct Struct_1_t *)a2;
    arg_4a0 = a1;
    a2 += 136;
    arg_4a8 = (__int64)ptr;
    if ((ptr->field_A1 == 0)) {
        i = ptr->field_A0;
        a1 = dst + 976;
        sub_14003E430(a1);
        if (i == 0) JUMPOUT(0x14003977e);
    } else {
        a1 = dst + 976;
        sub_14003E430(a1, a2);
    }
    if (arg_3d0 != 1) JUMPOUT(0x14003977e);
    sub_14002EDF0(0, 4);
    if (dst2 == 0) JUMPOUT(0x14003d334);
    *dst2 = 0x48544150;
    a1 = (__int64)dst2;
    a1 += 4;
    arg_510 = (__int64)dst2;
    arg_518 = a1;
    arg_520 = 0;
    a1 = dst + 0x4D0;
    a2 = dst + 0x510;
    arg_550 = (__int64)dst2;
    sub_14002F640(a1, a2);
    v_30 = 4;
    i = arg_550;
    v_28 = i;
    v_20 = 4;
    v_18 = 0;
    xmm0 = _mm_loadu_si128((__m128i *)&arg_4d0);
    _mm_storeu_si128((__m128i *)&v_10, xmm0);
    v7 = arg_4e0;
    *dst = v7;
    src2 = (__int64 *)arg_3d8;
    v11 = src;
    arg_548 = v11;
    if (src2 == 0) JUMPOUT(0x1400397a8);
    dst2 = *dst;
    arg_568 = (__int64)dst2;
    v8 = arg_3e0;
    v11 = 0;
    ptr = src2 + 360;
    v9 = *(src2 + 978);
    v10 = v9 * 56;
    i = -1;
    do {
        if (v10 == 0) JUMPOUT(0x140039757);
        v6 = ptr->field_28;
        v5 = ptr->field_30;
        v_20 = 1;
        a1 = arg_548;
        a2 = arg_568;
        off_1401081D8(a1, a2, v6, v5);
        ++i;
        if (dst2 == 1) JUMPOUT(0x140039760);
        if (dst2 == 2) JUMPOUT(0x140039783);
        ptr += 56;
        v10 -= 56;
    } while (dst2 == 3);
    return sub_14003D132();
}