// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400D2A60(size_t *a1, size_t *a2) {
    int arg_1;
    int arg_2;
    int v_20;
    __int64 v_30;
    int v_a0;
    int v_a8;
    __int64 *dst;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v2;
    __int64 i;
    __int64 *dst2;
    __int64 v9;
    __int64 v13;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __int64 v5;

    dst = (__int64 *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 3);
    if (result != 0) {
        ptr = (struct Struct_1_t *)result;
        *result = 0x3148;
        arg_2 = 192;
        result = ptr2->field_0;
        v2 = ptr2->field_10;
        result -= v2;
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr2, v2, 3, 1);
            v2 = ptr2->field_10;
        }
        result = ptr2->field_8;
        a1 = ptr->field_2;
        *(result + v2 + 2) = a1;
        a1 = ptr->field_0;
        *(result + v2) = a1;
        v2 += 3;
        ptr2->field_10 = v2;
        off_140108030(a1);
        off_140108038(result, 0, ptr);
        i = *dst;
        result = i + 1;
        *dst = result;
        sub_14002EDF0(0, 3);
        ptr = (struct Struct_1_t *)result;
        *result = 0x8948;
        arg_2 = 231;
        result = ptr2->field_0;
        result -= v2;
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr2, v2, 3, 1);
            v2 = ptr2->field_10;
        }
        result = ptr2->field_8;
        a1 = ptr->field_2;
        *(result + v2 + 2) = a1;
        a1 = ptr->field_0;
        *(result + v2) = a1;
        v2 += 3;
        ptr2->field_10 = v2;
        off_140108030(a1);
        off_140108038(result, 0, ptr);
        sub_14002EDF0(0, 6);
        if (result == 0) {
            sub_1400F3326(1, 6);
            v2 = v6;
            ptr = (struct Struct_1_t *)v5;
            dst = (__int64 *)a2;
            ptr2 = (struct Struct_2_t *)a1;
            sub_14002EDF0(0, 8);
            if (result == 0) JUMPOUT(0x1400d34ab);
            dst2 = result;
            *dst2 = result;
            v9 = ptr2->field_0;
            i = ptr2->field_10;
            result = (__int64 *)v9;
            result -= i;
            v_30 = (__int64)ptr;
            if (result <= 7) JUMPOUT(0x1400d3376);
            ptr = ptr2->field_8;
            result = *dst2;
            *(__int64 *)(ptr + i) = (__int64)(result);
            i += 8;
            ptr2->field_10 = i;
            off_140108030(0x11024BC8D48);
            off_140108038(result, 0, dst2);
            v13 = *dst;
            result = (__int64 *)v9;
            result -= i;
            if (result <= 1) JUMPOUT(0x1400d33a2);
            *(__int64 *)(ptr + i) = (__int64)(0xC031);
            i += 2;
            ptr2->field_10 = i;
            result = v13 + 2;
            *dst = result;
            if (v9 == i) JUMPOUT(0x1400d33d2);
            *(__int64 *)(ptr + i) = (__int64)(185);
            ++i;
            ptr2->field_10 = i;
            result = ptr2->field_0;
            a1 = (size_t *)result;
            a1 -= i;
            if (a1 <= 3) JUMPOUT(0x1400d33ff);
            ptr = (struct Struct_1_t *)v_30;
            a1 = ptr2->field_8;
            *(a1 + i) = 136;
            i += 4;
            ptr2->field_10 = i;
            a2 = (size_t *)result;
            a2 -= i;
            if (a2 <= 2) JUMPOUT(0x1400d342b);
            v7 = v_a8;
            *(a1 + i + 2) = 170;
            *(a1 + i) = 0xF3FC;
            i += 3;
            ptr2->field_10 = i;
            result -= i;
            if (v2 > result) JUMPOUT(0x1400d345b);
            v8 = v_a0;
            a1 += i;
            sub_1400F27F0(a1, ptr, v2);
            i += v2;
            ptr2->field_10 = i;
            result = ptr2->field_0;
            result -= i;
            if (v7 > result) JUMPOUT(0x1400d3485);
            a1 = ptr2->field_8;
            a1 += i;
            sub_1400F27F0(a1, v8, v7);
            i += v7;
            ptr2->field_10 = i;
            v13 += 6;
            *dst = v13;
            return v13;
        } else {
            ptr = (struct Struct_1_t *)result;
            *result = 185;
            arg_1 = 472;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            a1 = ptr->field_4;
            *(result + v2 + 4) = a1;
            a1 = ptr->field_0;
            *(result + v2) = a1;
            v2 += 5;
            ptr2->field_10 = v2;
            off_140108030(a1);
            off_140108038(result, 0, ptr);
            result = ptr2->field_0;
            result -= v2;
            if (result <= 2) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 3, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2 + 2) = 170;
            *(result + v2) = 0xF3FC;
            v2 += 3;
            ptr2->field_10 = v2;
            result = i + 4;
            *dst = result;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xC0EF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xC9EF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xD2EF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xDBEF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = i + 8;
            *dst = result;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xE4EF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEDEF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xF6EF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 3) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 4, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xFFEF0F66;
            v2 += 4;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 192;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 201;
            v2 += 5;
            ptr2->field_10 = v2;
            result = i + 14;
            *dst = result;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 210;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 219;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 228;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 237;
            v2 += 5;
            ptr2->field_10 = v2;
            result = i + 18;
            *dst = result;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 246;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xEF0F4566;
            *(result + v2 + 4) = 255;
            v2 += 5;
            ptr2->field_10 = v2;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 1) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 2, 1);
                v2 = ptr2->field_10;
            }
            result = ptr2->field_8;
            *(result + v2) = 0xE3DB;
            v2 += 2;
            ptr2->field_10 = v2;
            i += 21;
            *dst = i;
            return i;
        }
    }
    do {
        sub_1400F3340(1, 3);
        return i;
    } while (result == 0);
    return (__int64)result;
}