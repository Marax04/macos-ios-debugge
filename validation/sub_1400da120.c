// inferred from 4 accesses on `i`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400FAE80();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400DA120(size_t *a1, size_t *a2, size_t *a3, int *a4) {
    __int64 rsp;
    __int64 arg_1;
    __int64 arg_2;
    int v_20;
    __int64 v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    int v_a0;
    __int64 *v_0;
    struct Struct_1_t *i;
    __int64 *result;
    __int64 i2;
    __int64 *i3;
    __int64 *dst;
    struct Struct_3_t *ptr2;
    __int64 *dst2;
    __int64 *dst3;
    struct Struct_2_t *ptr;

    v_60 = (int)a3;
    i = (struct Struct_1_t *)a1;
    result = *a1;
    i2 = a1[2];
    result -= i2;
    v_40 = (int)a4;
    if (result <= 1) {
        v_20 = 1;
        i3 = (__int64 *)a2;
        sub_1400F2D20(i, i2, 2, 1);
        a2 = (size_t *)i3;
        i2 = i->field_10;
    }
    dst = i->field_8;
    *(dst + i2) = 0xDB31;
    result = *a2;
    i2 += 2;
    i->field_10 = i2;
    v_30 = (__int64)result;
    ++result;
    v_38 = (int)a2;
    *a2 = result;
    i3 = 0;
    result = (__int64 *)v_60;
    ptr2 = *(__int64 *)((__int64)result + (__int64)i3);
    sub_14002EDF0(0, 8);
    while (result != 0) {
        v_48 = 8;
        v_50 = (__int64)result;
        *result = 139;
        v_58 = 1;
        a4 = i3 + 32;
        a1 = rsp + 72;
        sub_1400D4F50(a1, 0, 4, a4);
        dst2 = (__int64 *)v_48;
        dst3 = (__int64 *)v_50;
        ptr = (struct Struct_2_t *)v_58;
        result = i->field_0;
        result -= i2;
        if (ptr > result) {
            v_20 = 1;
            sub_1400F2D20(i, i2, ptr, 1);
            dst = i->field_8;
            i2 = i->field_10;
        }
        dst += i2;
        sub_1400F27F0(dst, dst3, ptr);
        i2 += (__int64)ptr;
        i->field_10 = i2;
        if (dst2 == 0) {
            result = i->field_0;
            if (result == i2) {
                v_20 = 1;
                sub_1400F2D20(i, i2, 1, 1);
                result = i->field_0;
                i2 = i->field_10;
            }
            dst = i->field_8;
            *(dst + i2) = 53;
            ++i2;
            i->field_10 = i2;
            a1 = (size_t *)result;
            a1 -= i2;
            if (a1 <= 3) {
                v_20 = 1;
                sub_1400F2D20(i, i2, 4, 1);
                i2 = i->field_10;
                result = i->field_0;
                dst = i->field_8;
            }
            ptr2 = __builtin_bswap32(ptr2);
            *(dst + i2) = ptr2;
            i2 += 4;
            i->field_10 = i2;
            result -= i2;
            if (result <= 1) {
                v_20 = 1;
                sub_1400F2D20(i, i2, 2, 1);
                dst = i->field_8;
                i2 = i->field_10;
            }
            *(dst + i2) = 0xC309;
            i2 += 2;
            i->field_10 = i2;
            i3 += 4;
            result = i->field_0;
            a1 = (size_t *)result;
            a1 -= i2;
            if (a1 <= 1) {
                v_20 = 1;
                sub_1400F2D20(i, i2, 2, 1);
                result = i->field_0;
                i2 = i->field_10;
            }
            ptr = (struct Struct_2_t *)v_40;
            i3 = (__int64 *)v_38;
            dst2 = (__int64 *)v_30;
            a1 = i->field_8;
            *(a1 + i2) = 0xDB85;
            i2 += 2;
            i->field_10 = i2;
            result -= i2;
            a2 = (size_t *)i2;
            if (result <= 5) {
                v_20 = 1;
                sub_1400F2D20(i, i2, 6, 1);
                a1 = i->field_8;
                a2 = i->field_10;
            }
            *(__int64 *)((__int64)a1 + (__int64)a2 + 4) = 0;
            *(__int64 *)((__int64)a1 + (__int64)a2) = 0x850F;
            a2 += 6;
            i->field_10 = a2;
            dst2 += 27;
            *i3 = dst2;
            i3 = ptr->field_10;
            if (i3 == ptr->field_0) {
                sub_1400FAE80(ptr, a2);
            }
            result = ptr->field_8;
            v_0[(__int64)i3] = i2;
            ++i3;
            ptr->field_10 = i3;
            return (__int64)i3;
        }
        off_140108030();
        off_140108038(result, 0, dst3);
        return (__int64)i3;
    }
    sub_1400F3326(1, 8);
    dst3 = (__int64 *)a4;
    i = (struct Struct_1_t *)a3;
    i3 = (__int64 *)a2;
    ptr = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result == 0) JUMPOUT(0x1400dab6f);
    ptr2 = (struct Struct_3_t *)result;
    *(__int64 *)ptr2 = (__int64)(result);
    result = ptr->field_0;
    i2 = ptr->field_10;
    result -= i2;
    if (result <= 7) JUMPOUT(0x1400da85f);
    dst2 = ptr->field_8;
    result = ptr2->field_0;
    *(dst2 + i2) = result;
    i2 += 8;
    ptr->field_10 = i2;
    off_140108030(0xD0249C8B4C);
    off_140108038(result, 0, ptr2);
    dst = *i3;
    sub_14002EDF0(0, 10);
    if (result == 0) JUMPOUT(0x1400dab7e);
    ptr2 = (struct Struct_3_t *)result;
    *result = 0xBA49;
    arg_2 = (__int64)i;
    i = ptr->field_0;
    result = (__int64 *)i;
    result -= i2;
    v_30 = (__int64)i3;
    i3 = dst3;
    if (result <= 9) JUMPOUT(0x1400da888);
    dst3 = (__int64 *)v_a0;
    result = ptr2->field_8;
    *(dst2 + i2 + 8) = result;
    result = ptr2->field_0;
    *(dst2 + i2) = result;
    i2 += 10;
    ptr->field_10 = i2;
    off_140108030();
    off_140108038(result, 0, ptr2);
    i -= i2;
    if (i <= 2) JUMPOUT(0x1400da8b8);
    *(dst2 + i2 + 2) = 211;
    *(dst2 + i2) = 0x294D;
    i2 += 3;
    ptr->field_10 = i2;
    result = dst3;
    result = (__int64 *)((__int64)(__int64)result >> 32);
    if ((result != 0)) JUMPOUT(0x1400dab8d);
    if (dst3 > 0x1FFFFFFF) JUMPOUT(0x1400dab46);
    sub_14002EDF0(0, 5);
    if (result == 0) JUMPOUT(0x1400dabb6);
    i = (struct Struct_1_t *)result;
    ptr2 =  + (__int64)(__int64)dst3*4;
    *result = 233;
    arg_1 = (__int64)ptr2;
    dst3 = ptr->field_0;
    result = dst3;
    result -= i2;
    if (result <= 4) JUMPOUT(0x1400da8e5);
    dst2 = ptr->field_8;
    result = i->field_4;
    *(dst2 + i2 + 4) = result;
    result = i->field_0;
    *(dst2 + i2) = result;
    i2 += 5;
    ptr->field_10 = i2;
    off_140108030();
    off_140108038(result, 0, i);
    dst3 -= i2;
    i = (struct Struct_1_t *)i2;
    if (ptr2 > dst3) JUMPOUT(0x1400da911);
    a1 = (__int64)dst2 + (__int64)i;
    sub_1400F27F0(a1, i3, ptr2);
    i = (struct Struct_1_t *)((__int64)i + (__int64)ptr2);
    ptr->field_10 = i;
    result = dst + 5;
    dst3 = (__int64 *)v_30;
    *dst3 = result;
    result = (__int64 *)i;
    result += 7;
    ptr2 = (struct Struct_3_t *)v_a0;
    if ((result < 0)) JUMPOUT(0x1400dabc5);
    i2 -= (__int64)result;
    result = (__int64 *)i2;
    if (i2 != i2) JUMPOUT(0x1400dabee);
    result = ptr->field_0;
    result = (__int64 *)((__int64)result - (__int64)i);
    if (result <= 2) JUMPOUT(0x1400da93b);
    *(__int64 *)((__int64)dst2 + (__int64)i + 2) = 53;
    *(__int64 *)((__int64)dst2 + (__int64)i) = 0x8D48;
    i += 3;
    ptr->field_10 = i;
    a2 = ptr->field_0;
    result = (__int64 *)a2;
    result = (__int64 *)((__int64)result - (__int64)i);
    if (result <= 3) JUMPOUT(0x1400da968);
    result = ptr->field_8;
    *(__int64 *)((__int64)result + (__int64)i) = i2;
    i += 4;
    ptr->field_10 = i;
    if (a2 == i) JUMPOUT(0x1400da994);
    *(__int64 *)((__int64)result + (__int64)i) = 185;
    ++i;
    ptr->field_10 = i;
    a2 = (size_t *)((__int64)a2 - (__int64)i);
    if (a2 <= 3) JUMPOUT(0x1400da9c1);
    *(__int64 *)((__int64)result + (__int64)i) = ptr2;
    i += 4;
    ptr->field_10 = i;
    result = dst + 7;
    *dst3 = result;
    sub_14002EDF0(0, 8);
    if (result == 0) JUMPOUT(0x1400dab6f);
    dst2 = result;
    *dst2 = result;
    ptr2 = ptr->field_0;
    result = (__int64 *)ptr2;
    result = (__int64 *)((__int64)result - (__int64)i);
    if (result <= 7) JUMPOUT(0x1400da9ee);
    dst3 = ptr->field_8;
    result = *dst2;
    *(__int64 *)((__int64)dst3 + (__int64)i) = result;
    i2 = i + 8;
    ptr->field_10 = i2;
    off_140108030(0xD0249C8B48);
    off_140108038(result, 0, dst2);
    result = (__int64 *)ptr2;
    result -= i2;
    a2 = (size_t *)i2;
    if (result <= 1) JUMPOUT(0x1400daa1a);
    *(__int64 *)((__int64)dst3 + (__int64)a2) = 0x68B;
    a2 += 2;
    ptr->field_10 = a2;
    ptr2 = (struct Struct_3_t *)((__int64)ptr2 - (__int64)a2);
    if (ptr2 <= 2) JUMPOUT(0x1400daa4a);
    *(__int64 *)((__int64)dst3 + (__int64)a2 + 2) = 216;
    *(__int64 *)((__int64)dst3 + (__int64)a2) = 328;
    a2 += 3;
    ptr->field_10 = a2;
    result = ptr->field_0;
    a1 = (size_t *)result;
    a1 = (size_t *)((__int64)a1 - (__int64)a2);
    if (a1 <= 2) JUMPOUT(0x1400daa74);
    i3 = (__int64 *)v_30;
    a1 = ptr->field_8;
    *(__int64 *)((__int64)a1 + (__int64)a2 + 2) = 24;
    *(__int64 *)((__int64)a1 + (__int64)a2) = 332;
    a2 += 3;
    ptr->field_10 = a2;
    a3 = dst + 11;
    *i3 = a3;
    a3 = (size_t *)result;
    a3 = (size_t *)((__int64)a3 - (__int64)a2);
    if (a3 <= 3) JUMPOUT(0x1400daa9d);
    *(__int64 *)((__int64)a1 + (__int64)a2) = 0x4C68348;
    a2 += 4;
    ptr->field_10 = a2;
    result = (__int64 *)((__int64)result - (__int64)a2);
    if (result <= 1) JUMPOUT(0x1400daaca);
    *(__int64 *)((__int64)a1 + (__int64)a2) = 0xC9FF;
    result = a2 + 2;
    ptr->field_10 = result;
    if (i > 0x7FFFFFF7) JUMPOUT(0x1400dab46);
    if (a2 > 0x7FFFFFFB) JUMPOUT(0x1400dab46);
    i2 -= (__int64)result;
    i2 += 0xFFFFFFFE;
    a1 = (size_t *)i2;
    if (i2 != i2) JUMPOUT(0x1400daaf4);
    a1 = ptr->field_0;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 1) JUMPOUT(0x1400dab1d);
    a1 = ptr->field_8;
    i2 <<= 8;
    i2 |= 117;
    *(__int64 *)((__int64)a1 + (__int64)result) = i2;
    result += 2;
    ptr->field_10 = result;
    dst += 14;
    *i3 = dst;
    return (__int64)result;
}