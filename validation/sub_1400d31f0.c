// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400D31F0(size_t *a1, size_t *a2, int *a3, int a4) {
    int arg_2;
    int arg_4;
    int v_20;
    __int64 v_30;
    int v_a0;
    int v_a8;
    __int64 v2;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __int64 v9;
    __int64 *result;
    __int64 *dst2;
    __int64 i;
    __int64 *dst3;

    v2 = a4;
    ptr2 = (struct Struct_2_t *)a3;
    dst = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 8);
    if (result == 0) {
        sub_1400F3326(1, 8);
        v9 = (__int64)a3;
        dst = (__int64 *)a2;
        ptr = (struct Struct_1_t *)a1;
        sub_14002EDF0(0, 8);
        if (result == 0) JUMPOUT(0x1400d383c);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0x244C8B48;
        arg_4 = 56;
        result = ptr->field_0;
        v2 = ptr->field_10;
        result -= v2;
        if (result <= 4) JUMPOUT(0x1400d3736);
        dst2 = ptr->field_8;
        result = ptr2->field_4;
        *(dst2 + v2 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 5;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        i = *dst;
        sub_14002EDF0(0, 8);
        if (result == 0) JUMPOUT(0x1400d383c);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0x24548B48;
        arg_4 = 64;
        result = ptr->field_0;
        result -= v2;
        if (result <= 4) JUMPOUT(0x1400d375f);
        result = ptr2->field_4;
        *(dst2 + v2 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 5;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        result = i + 2;
        *dst = result;
        sub_14002EDF0(0, 6);
        if (result == 0) JUMPOUT(0x1400d384b);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0xB841;
        arg_2 = v9;
        result = ptr->field_0;
        result -= v2;
        if (result <= 5) JUMPOUT(0x1400d378c);
        result = ptr2->field_4;
        *(dst2 + v2 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 6;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        sub_14002EDF0(0, 8);
        if (result == 0) JUMPOUT(0x1400d383c);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0x244C8D4C;
        arg_4 = 48;
        result = ptr->field_0;
        result -= v2;
        if (result <= 4) JUMPOUT(0x1400d37b9);
        dst2 = ptr->field_8;
        result = ptr2->field_4;
        *(dst2 + v2 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 5;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        result = i + 4;
        *dst = result;
        sub_14002EDF0(0, 8);
        if (result == 0) JUMPOUT(0x1400d383c);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0x24448B48;
        arg_4 = 32;
        result = ptr->field_0;
        result -= v2;
        if (result <= 4) JUMPOUT(0x1400d37e2);
        result = ptr2->field_4;
        *(dst2 + v2 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 5;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        sub_14002EDF0(0, 3);
        if (result == 0) JUMPOUT(0x1400d385a);
        ptr2 = (struct Struct_2_t *)result;
        *result = 0xD0FF;
        result = ptr->field_0;
        result -= v2;
        if (result <= 1) JUMPOUT(0x1400d380f);
        result = ptr2->field_0;
        *(dst2 + v2) = result;
        v2 += 2;
        ptr->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr2);
        i += 6;
        *dst = i;
        return i;
    } else {
        dst3 = result;
        *dst3 = result;
        dst2 = ptr->field_0;
        i = ptr->field_10;
        result = dst2;
        result -= i;
        v_30 = (__int64)ptr2;
        if (result <= 7) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, 8, 1);
            dst2 = ptr->field_0;
            i = ptr->field_10;
        }
        ptr2 = ptr->field_8;
        result = *dst3;
        *(__int64 *)(ptr2 + i) = (__int64)(result);
        i += 8;
        ptr->field_10 = i;
        off_140108030(0x11024BC8D48);
        off_140108038(result, 0, dst3);
        v9 = *dst;
        result = dst2;
        result -= i;
        if (result <= 1) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, 2, 1);
            i = ptr->field_10;
            dst2 = ptr->field_0;
            ptr2 = ptr->field_8;
        }
        *(__int64 *)(ptr2 + i) = (__int64)(0xC031);
        i += 2;
        ptr->field_10 = i;
        result = v9 + 2;
        *dst = result;
        if (dst2 == i) {
            v_20 = 1;
            sub_1400F2D20(ptr, dst2, 1, 1);
            ptr2 = ptr->field_8;
            i = ptr->field_10;
        }
        *(__int64 *)(ptr2 + i) = (__int64)(185);
        ++i;
        ptr->field_10 = i;
        result = ptr->field_0;
        a1 = (size_t *)result;
        a1 -= i;
        if (a1 <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, 4, 1);
            result = ptr->field_0;
            i = ptr->field_10;
        }
        ptr2 = (struct Struct_2_t *)v_30;
        a1 = ptr->field_8;
        *(a1 + i) = 136;
        i += 4;
        ptr->field_10 = i;
        a2 = (size_t *)result;
        a2 -= i;
        if (a2 <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, 3, 1);
            i = ptr->field_10;
            result = ptr->field_0;
            a1 = ptr->field_8;
        }
        dst2 = (__int64 *)v_a8;
        *(a1 + i + 2) = 170;
        *(a1 + i) = 0xF3FC;
        i += 3;
        ptr->field_10 = i;
        result -= i;
        if (v2 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, v2, 1);
            a1 = ptr->field_8;
            i = ptr->field_10;
        }
        dst3 = (__int64 *)v_a0;
        a1 += i;
        sub_1400F27F0(a1, ptr2, v2);
        i += v2;
        ptr->field_10 = i;
        result = ptr->field_0;
        result -= i;
        if (dst2 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr, i, dst2, 1);
            i = ptr->field_10;
        }
        a1 = ptr->field_8;
        a1 += i;
        sub_1400F27F0(a1, dst3, dst2);
        i += (__int64)dst2;
        ptr->field_10 = i;
        v9 += 6;
        *dst = v9;
        return (__int64)result;
    }
}