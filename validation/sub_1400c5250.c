// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `i`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_1400F3B80();
__int64 sub_1400C679C();
__int64 sub_1400F37A0();
__int64 sub_1400FAE80();
extern __int64 off_14011B750;
extern __int64 off_14011B730;
extern __int64 off_14011D3F8;
extern __int64 off_14000E2E0;
extern __int64 off_14011C9E0;
extern __int64 off_14011CA00;

__int64 __fastcall sub_1400C5250(size_t *a1, size_t *a2, int *a3, size_t *a4) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    int v_68;
    __int64 v_70;
    __int64 v_78;
    int v_b8;
    int v_e0;
    int v_e8;
    __int64 *v_0;
    __m128i xmm0;
    __int64 *result;
    struct Struct_3_t *i;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __int64 v11;
    struct Struct_2_t *ptr2;
    __int64 v9;
    __int64 v6;
    __int64 v10;
    __int64 *v8;
    __int64 v7;

    xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
    _mm_storeu_si128((__m128i *)&v_70, xmm0);
    result = *a1;
    i = a1[2];
    dst = result;
    dst = (__int64 *)((__int64)dst - (__int64)i);
    if (dst <= 1) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        v11 = (__int64)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v9 = (__int64)a2;
        sub_1400F2D20(a1, i, 2, 1);
        a4 = (size_t *)v11;
        a2 = (size_t *)v9;
        a3 = (int *)ptr;
        result = ptr2->field_0;
        i = ptr2->field_10;
    }
    dst = (__int64 *)arg_8;
    *(__int64 *)((__int64)dst + (__int64)i) = 0x310F;
    i += 2;
    a1[2] = i;
    v9 = *a2;
    v6 = (__int64)result;
    v6 -= (__int64)i;
    if (v6 <= 3) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        v11 = (__int64)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, i, 4, 1);
        a4 = (size_t *)v11;
        a2 = (size_t *)v10;
        a3 = (int *)ptr;
        i = ptr2->field_10;
        result = ptr2->field_0;
        dst = ptr2->field_8;
    }
    *(__int64 *)((__int64)dst + (__int64)i) = 0x20E2C148;
    i += 4;
    a1[2] = i;
    result = (__int64 *)((__int64)result - (__int64)i);
    if (result <= 2) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        v11 = (__int64)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, i, 3, 1);
        a4 = (size_t *)v11;
        a2 = (size_t *)v10;
        a3 = (int *)ptr;
        dst = ptr2->field_8;
        i = ptr2->field_10;
    }
    *(__int64 *)((__int64)dst + (__int64)i + 2) = 208;
    *(__int64 *)((__int64)dst + (__int64)i) = 0x948;
    i += 3;
    a1[2] = i;
    result = *a1;
    dst = result;
    dst = (__int64 *)((__int64)dst - (__int64)i);
    if (dst <= 2) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        v11 = (__int64)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, i, 3, 1);
        a4 = (size_t *)v11;
        a2 = (size_t *)v10;
        a3 = (int *)ptr;
        result = ptr2->field_0;
        i = ptr2->field_10;
    }
    dst = (__int64 *)arg_8;
    *(__int64 *)((__int64)dst + (__int64)i + 2) = 195;
    *(__int64 *)((__int64)dst + (__int64)i) = 0x8949;
    i += 3;
    a1[2] = i;
    v6 = v9 + 4;
    *a2 = v6;
    if (result == i) {
        v_20 = 1;
        i = (struct Struct_3_t *)a3;
        ptr = (struct Struct_1_t *)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, result, 1, 1);
        a4 = (size_t *)ptr;
        a2 = (size_t *)v10;
        a3 = (int *)i;
        i = ptr2->field_10;
        result = ptr2->field_0;
        dst = ptr2->field_8;
    }
    *(__int64 *)((__int64)dst + (__int64)i) = 185;
    ++i;
    a1[2] = i;
    result = (__int64 *)((__int64)result - (__int64)i);
    if (result <= 3) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        v11 = (__int64)a4;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, i, 4, 1);
        a4 = (size_t *)v11;
        a2 = (size_t *)v10;
        a3 = (int *)ptr;
        dst = ptr2->field_8;
        i = ptr2->field_10;
    }
    *(__int64 *)((__int64)dst + (__int64)i) = a4;
    result = i + 4;
    a1[2] = result;
    a4 = *a1;
    a4 = (size_t *)((__int64)a4 - (__int64)result);
    if (a4 <= 1) {
        v_20 = 1;
        ptr = (struct Struct_1_t *)a3;
        ptr2 = (struct Struct_2_t *)a1;
        v10 = (__int64)a2;
        sub_1400F2D20(ptr2, result, 2, 1);
        a1 = (size_t *)ptr2;
        a2 = (size_t *)v10;
        result = ptr2->field_10;
    }
    a4 = (size_t *)arg_8;
    *(__int64 *)((__int64)a4 + (__int64)result) = 0xC9FF;
    ptr2 = result + 2;
    a1[2] = ptr2;
    dst = result;
    dst += 4;
    if ((dst < 0)) {
        result = &off_14011B750;
        v_20 = (__int64)result;
        a1 = &off_14011B730;
        a4 = &off_14011D3F8;
        a3 = rsp + 64;
        sub_1400F3B80(a1, 28, a3, a4);
        v8 = (__int64 *)a4;
        i = (struct Struct_3_t *)a2;
        v_b8 = (int)a1;
        result = a4[49];
        v_70 = (__int64)result;
        v_28 = (int)a3;
        if (result != 2) JUMPOUT(0x1400c5bf0);
        result = i->field_0;
        v7 = i->field_10;
        a1 = (size_t *)result;
        a1 -= v7;
        v_58 = v7;
        if (a1 <= 6) JUMPOUT(0x1400c9069);
        a1 = i->field_8;
        *(a1 + v7 + 3) = 0;
        *(a1 + v7) = 0x358D48;
        v7 += 7;
        i->field_10 = v7;
        ptr2 = *a3;
        a2 = (size_t *)result;
        a2 -= v7;
        if (a2 <= 1) JUMPOUT(0x1400c909c);
        *(a1 + v7) = 0xC033;
        v7 += 2;
        i->field_10 = v7;
        result -= v7;
        if (result <= 2) JUMPOUT(0x1400c90d1);
        *(a1 + v7 + 2) = 201;
        *(a1 + v7) = 0x3148;
        v7 += 3;
        i->field_10 = v7;
        result = ptr2 + 3;
        *a3 = result;
        result = i->field_0;
        a1 = (size_t *)result;
        a1 -= v7;
        v10 = v7;
        if (a1 <= 3) JUMPOUT(0x1400c9103);
        a1 = i->field_8;
        *(a1 + v10) = 0xE1CB60F;
        v10 += 4;
        i->field_10 = v10;
        a2 = (size_t *)result;
        a2 -= v10;
        if (a2 <= 1) JUMPOUT(0x1400c9134);
        *(a1 + v10) = 0xD801;
        v10 += 2;
        i->field_10 = v10;
        result -= v10;
        if (result <= 2) JUMPOUT(0x1400c9169);
        *(a1 + v10 + 2) = 193;
        *(a1 + v10) = 0xFF48;
        v10 += 3;
        i->field_10 = v10;
        result = i->field_0;
        result -= v10;
        a1 = (size_t *)v10;
        if (result <= 6) JUMPOUT(0x1400c919b);
        result = i->field_8;
        *(__int64 *)((__int64)result + (__int64)a1 + 3) = 0;
        *(__int64 *)((__int64)result + (__int64)a1) = 0xF98148;
        v11 = a1 + 7;
        i->field_10 = v11;
        a2 = ptr2 + 7;
        *a3 = a2;
        a1 += 13;
        if ((a1 < 0)) JUMPOUT(0x1400caee9);
        v7 -= (__int64)a1;
        a1 = (size_t *)v7;
        if (v7 != v7) JUMPOUT(0x1400cafb2);
        a1 = i->field_0;
        a2 = a1;
        a2 -= v11;
        if (a2 <= 1) JUMPOUT(0x1400c91e1);
        *(result + v11) = 0x820F;
        v11 += 2;
        i->field_10 = v11;
        a1 -= v11;
        if (a1 <= 3) JUMPOUT(0x1400c9216);
        *(result + v11) = v7;
        v11 += 4;
        i->field_10 = v11;
        result = i->field_0;
        a1 = (size_t *)result;
        a1 -= v11;
        a2 = (size_t *)v11;
        if (a1 <= 5) JUMPOUT(0x1400c9248);
        a1 = i->field_8;
        *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
        *(__int64 *)((__int64)a1 + (__int64)a2) = 0x9E8B;
        a2 += 6;
        i->field_10 = a2;
        a4 = (size_t *)result;
        a4 = (size_t *)((__int64)a4 - (__int64)a2);
        if (a4 <= 1) JUMPOUT(0x1400c9279);
        *(__int64 *)((__int64)a1 + (__int64)a2) = 0xD839;
        a2 += 2;
        i->field_10 = a2;
        result = (__int64 *)((__int64)result - (__int64)a2);
        a4 = a2;
        if (result <= 5) JUMPOUT(0x1400c92ab);
        *(__int64 *)((__int64)a1 + (__int64)a4 + 4) = 0;
        *(__int64 *)((__int64)a1 + (__int64)a4) = 0x850F;
        a4 += 6;
        i->field_10 = a4;
        ptr2 += 11;
        *a3 = ptr2;
        result = 1;
        v_78 = (__int64)result;
        result = 4;
        v_48 = (__int64)result;
        v_68 = 0;
        v_50 = (__int64)a2;
        if (*(v8 + 104) != 0) JUMPOUT(0x1400c6727);
        return sub_1400C679C();
    } else {
        i = (struct Struct_3_t *)((__int64)i - (__int64)result);
        result = (__int64 *)i;
        if (i != i) {
            result = rsp + 112;
            v_30 = (__int64)result;
            result = &off_14000E2E0;
            v_38 = (__int64)result;
            result = &off_14011C9E0;
            v_40 = (__int64)result;
            v_48 = 2;
            v_60 = 0;
            result = rsp + 48;
            v_50 = (__int64)result;
            v_58 = 1;
            a2 = &off_14011CA00;
            a1 = rsp + 64;
            sub_1400F37A0(a1, a2, ptr);
        } else {
            result = *a1;
            dst = result;
            dst = (__int64 *)((__int64)dst - (__int64)ptr2);
            if (dst <= 1) {
                v_20 = 1;
                v10 = (__int64)a3;
                ptr = (struct Struct_1_t *)a1;
                v7 = (__int64)a2;
                sub_1400F2D20(a1, ptr2, 2, 1);
                a2 = (size_t *)v7;
                a3 = (int *)v10;
                ptr2 = ptr->field_10;
                result = ptr->field_0;
                a4 = ptr->field_8;
            }
            i = (struct Struct_3_t *)((__int64)(__int64)i << 8);
            i = (struct Struct_3_t *)((__int64)(__int64)i | 117);
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = i;
            ptr2 += 2;
            a1[2] = ptr2;
            dst = v9 + 7;
            *a2 = dst;
            result = (__int64 *)((__int64)result - (__int64)ptr2);
            if (result <= 1) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(ptr, ptr2, 2, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                a4 = i->field_8;
                ptr2 = i->field_10;
            }
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x310F;
            ptr2 += 2;
            a1[2] = ptr2;
            result = *a1;
            a4 = (size_t *)result;
            a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
            if (a4 <= 3) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 4, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                result = i->field_0;
                ptr2 = i->field_10;
            }
            a4 = (size_t *)arg_8;
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x20E2C148;
            ptr2 += 4;
            a1[2] = ptr2;
            dst = result;
            dst = (__int64 *)((__int64)dst - (__int64)ptr2);
            if (dst <= 2) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 3, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                ptr2 = i->field_10;
                result = i->field_0;
                a4 = i->field_8;
            }
            *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 208;
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x948;
            ptr2 += 3;
            a1[2] = ptr2;
            result = (__int64 *)((__int64)result - (__int64)ptr2);
            if (result <= 2) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 3, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                a4 = i->field_8;
                ptr2 = i->field_10;
            }
            *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 216;
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x294C;
            ptr2 += 3;
            a1[2] = ptr2;
            result = v9 + 11;
            *a2 = result;
            result = *a1;
            a4 = (size_t *)result;
            a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
            if (a4 <= 1) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 2, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                result = i->field_0;
                ptr2 = i->field_10;
            }
            ptr = (struct Struct_1_t *)v_e0;
            a4 = (size_t *)arg_8;
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0xB948;
            ptr2 += 2;
            a1[2] = ptr2;
            dst = result;
            dst = (__int64 *)((__int64)dst - (__int64)ptr2);
            if (dst <= 7) {
                v_20 = 1;
                v10 = (__int64)a3;
                i = (struct Struct_3_t *)a1;
                v7 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 8, 1);
                a2 = (size_t *)v7;
                a3 = (int *)v10;
                ptr2 = i->field_10;
                result = i->field_0;
                a4 = i->field_8;
            }
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = ptr;
            ptr2 += 8;
            a1[2] = ptr2;
            result = (__int64 *)((__int64)result - (__int64)ptr2);
            if (result <= 2) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 3, 1);
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                a4 = i->field_8;
                ptr2 = i->field_10;
            }
            *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 200;
            *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x3948;
            ptr2 += 3;
            a1[2] = ptr2;
            a4 = *a1;
            a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
            result = (__int64 *)ptr2;
            if (a4 <= 5) {
                v_20 = 1;
                ptr = (struct Struct_1_t *)a3;
                i = (struct Struct_3_t *)a1;
                v10 = (__int64)a2;
                sub_1400F2D20(i, ptr2, 6, 1);
                a1 = (size_t *)i;
                a2 = (size_t *)v10;
                a3 = (int *)ptr;
                result = i->field_10;
            }
            a4 = (size_t *)arg_8;
            *(__int64 *)((__int64)a4 + (__int64)result + 4) = 0;
            *(__int64 *)((__int64)a4 + (__int64)result) = 0x870F;
            result += 6;
            a1[2] = result;
            v9 += 14;
            *a2 = v9;
            i = a3[2];
            if (i == *a3) {
                ptr = (struct Struct_1_t *)a3;
                sub_1400FAE80(a3, a2, a3, a4);
                a3 = (int *)ptr;
            }
            result = (__int64 *)arg_8;
            v_0[(__int64)i] = ptr2;
            ++i;
            a3[2] = i;
            return (__int64)i;
        }
        return (__int64)result;
    }
}