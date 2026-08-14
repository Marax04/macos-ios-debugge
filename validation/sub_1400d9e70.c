// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3326();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3B80();
__int64 sub_1400DA33A();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011B7D8;
extern __int64 off_14011B7C0;

__int64 __fastcall sub_1400D9E70(size_t *a1, int *a2, int *str, int a4) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    __int64 v_50;
    int v_58;
    int v_60;
    __int64 v11;
    __int64 *dst;
    struct Struct_3_t *ptr3;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 i;
    __int64 *dst2;
    __int64 v8;
    __int64 v5;
    __int64 *dst3;

    v11 = a4;
    dst = (__int64 *)str;
    ptr3 = (struct Struct_3_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        ptr = (struct Struct_1_t *)result;
        *result = 0x244C8D48;
        *(result + 4) = 32;
        result = ptr3->field_0;
        i = ptr3->field_10;
        result -= i;
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr3, i, 5, 1);
            i = ptr3->field_10;
        }
        dst2 = ptr3->field_8;
        result = ptr->field_4;
        *(dst2 + i + 4) = result;
        result = ptr->field_0;
        *(dst2 + i) = result;
        i += 5;
        ptr3->field_10 = i;
        off_140108030();
        off_140108038(result, 0, ptr);
        v8 = *dst;
        result = v8 + 1;
        v_40 = (__int64)dst;
        *dst = result;
        sub_14002EDF0(0, 8);
        if (result == 0) {
            sub_1400F3326(1, 8);
        } else {
            str = 8;
            v_30 = (__int64)result;
            *result = 0x8D48;
            v_38 = 2;
            a1 = rsp + 40;
            sub_1400D4F50(a1, 2, 4, v11);
            v11 = (__int64)str;
            ptr = (struct Struct_1_t *)v_30;
            v5 = v_38;
            result = ptr3->field_0;
            result -= i;
            if (v5 > result) {
                v_20 = 1;
                sub_1400F2D20(ptr3, i, v5, 1);
                dst2 = ptr3->field_8;
                i = ptr3->field_10;
            }
            a1 = dst2 + i;
            sub_1400F27F0(a1, ptr, v5);
            i += v5;
            ptr3->field_10 = i;
            if (v11 != 0) {
                off_140108030();
                off_140108038(result, 0, ptr);
            }
            ptr = (struct Struct_1_t *)v_40;
            if (ptr2 >= 0) {
                result = (__int64 *)i;
                result += 5;
                if ((result < 0)) {
                    result = &off_14011B3E0;
                    v_20 = (__int64)result;
                    a1 = &off_14011B3C3;
                    a4 = &off_14011D3F8;
                    sub_1400F3B80(a1, 23, str, a4);
                } else {
                    ptr2 = (struct Struct_2_t *)((__int64)ptr2 - (__int64)result);
                    result = (__int64 *)ptr2;
                    if (ptr2 == ptr2) {
                        if (ptr3->field_0 == i) {
                            v_20 = 1;
                            sub_1400F2D20(ptr3, i, 1, 1);
                            dst2 = ptr3->field_8;
                            i = ptr3->field_10;
                        }
                        *(dst2 + i) = 232;
                        ++i;
                        ptr3->field_10 = i;
                        result = ptr3->field_0;
                        result -= i;
                        if (result <= 3) {
                            v_20 = 1;
                            sub_1400F2D20(ptr3, i, 4, 1);
                            i = ptr3->field_10;
                        }
                        result = ptr3->field_8;
                        *(result + i) = ptr2;
                        i += 4;
                        ptr3->field_10 = i;
                        v8 += 3;
                        *(__int64 *)ptr = (__int64)(v8);
                        return v8;
                    }
                }
                result = &off_14011B7D8;
                v_20 = (__int64)result;
                a1 = &off_14011B7C0;
                a4 = &off_14011D3F8;
                sub_1400F3B80(a1, 21, str, a4);
                v_60 = (int)str;
                ptr2 = (struct Struct_2_t *)a1;
                result = *a1;
                i = a1[2];
                result -= i;
                v_40 = a4;
                if (result <= 1) JUMPOUT(0x1400da3cf);
                dst3 = ptr2->field_8;
                *(dst3 + i) = 0xDB31;
                result = *a2;
                i += 2;
                ptr2->field_10 = i;
                v_30 = (__int64)result;
                ++result;
                v_38 = (int)a2;
                *a2 = result;
                dst2 = 0;
                do {
                    result = (__int64 *)v_60;
                    dst = *(__int64 *)((__int64)result + (__int64)dst2);
                    sub_14002EDF0(0, 8);
                    if (result == 0) JUMPOUT(0x1400da457);
                    v_48 = 8;
                    v_50 = (__int64)result;
                    *result = 139;
                    v_58 = 1;
                    a4 = dst2 + 32;
                    a1 = rsp + 72;
                    sub_1400D4F50(a1, 0, 4, a4);
                    ptr = (struct Struct_1_t *)v_48;
                    v11 = v_50;
                    ptr3 = (struct Struct_3_t *)v_58;
                    result = ptr2->field_0;
                    result -= i;
                    if (ptr3 > result) JUMPOUT(0x1400da287);
                    dst3 += i;
                    sub_1400F27F0(dst3, v11, ptr3);
                    i += (__int64)ptr3;
                    ptr2->field_10 = i;
                    if (ptr == 0) {
                        result = ptr2->field_0;
                        if (result == i) JUMPOUT(0x1400da2b1);
                        dst3 = ptr2->field_8;
                        *(dst3 + i) = 53;
                        ++i;
                        ptr2->field_10 = i;
                        a1 = (size_t *)result;
                        a1 -= i;
                        if (a1 <= 3) JUMPOUT(0x1400da2dd);
                        dst = __builtin_bswap32(dst);
                        *(dst3 + i) = dst;
                        i += 4;
                        ptr2->field_10 = i;
                        result -= i;
                        if (result <= 1) JUMPOUT(0x1400da30d);
                        *(dst3 + i) = 0xC309;
                        i += 2;
                        ptr2->field_10 = i;
                        dst2 += 4;
                        return sub_1400DA33A();
                    }
                    off_140108030();
                    off_140108038(result, 0, v11);
                    return (__int64)dst2;
                } while (dst2 != 32);
                return (__int64)dst2;
            }
        }
        return (__int64)dst2;
    }
    return (__int64)result;
}