// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `i`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

// inferred from 3 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr4`
struct Struct_6_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F2D20();
__int64 sub_1400F3340();
__int64 sub_1400F3B80();
__int64 sub_1400DB34D();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011CA48;
extern __int64 off_14011CA2C;

__int64 __fastcall sub_1400DAEC0(size_t *a1, int *a2, int *str) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_28;
    int v_58;
    __int64 v_78;
    __int64 v_80;
    __int64 v_88;
    __int64 *dst;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    struct Struct_2_t *i;
    struct Struct_1_t *result;
    __int64 v10;
    __int64 *dst2;
    __int64 v9;
    struct Struct_6_t *ptr4;
    __int64 v5;
    struct Struct_5_t *ptr3;
    __int64 v6;

    dst = (__int64 *)str;
    ptr = (struct Struct_3_t *)a2;
    ptr2 = (struct Struct_4_t *)a1;
    sub_14002EDF0(0, 8);
    if (result == 0) {
        sub_1400F3326(1, 8);
    } else {
        i = (struct Struct_2_t *)result;
        *(__int64 *)result = (__int64)(0x244C8D48);
        result->field_4 = 32;
        result = ptr2->field_0;
        v10 = ptr2->field_10;
        result -= v10;
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr2, v10, 5, 1);
            v10 = ptr2->field_10;
        }
        dst2 = ptr2->field_8;
        result = i->field_4;
        *(dst2 + v10 + 4) = result;
        result = i->field_0;
        *(dst2 + v10) = result;
        v10 += 5;
        ptr2->field_10 = v10;
        off_140108030();
        off_140108038(result, 0, i);
        v9 = ptr->field_0;
        result = v9 + 1;
        *(__int64 *)ptr = (__int64)(result);
        sub_14002EDF0(0, 3);
        if (result == 0) {
            sub_1400F3340(1, 3);
        } else {
            ptr4 = (struct Struct_6_t *)result;
            *(__int64 *)result = (__int64)(0x894C);
            result->field_2 = 226;
            result = ptr2->field_0;
            result -= v10;
            if (result <= 2) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v10, 3, 1);
                dst2 = ptr2->field_8;
                v10 = ptr2->field_10;
            }
            result = ptr4->field_2;
            *(dst2 + v10 + 2) = result;
            result = ptr4->field_0;
            *(dst2 + v10) = result;
            i = v10 + 3;
            ptr2->field_10 = i;
            off_140108030();
            off_140108038(result, 0, ptr4);
            v10 += 8;
            if ((v10 < 0)) {
                result = &off_14011B3E0;
                v_20 = (__int64)result;
                a1 = &off_14011B3C3;
                v5 = &off_14011D3F8;
                sub_1400F3B80(a1, 23, str, v5);
            } else {
                dst -= v10;
                result = (struct Struct_1_t *)dst;
                if (dst == dst) {
                    if (ptr2->field_0 == i) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, i, 1, 1);
                        dst2 = ptr2->field_8;
                        i = ptr2->field_10;
                    }
                    *(__int64 *)((__int64)dst2 + (__int64)i) = 232;
                    ++i;
                    ptr2->field_10 = i;
                    result = ptr2->field_0;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                    if (result <= 3) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, i, 4, 1);
                        i = ptr2->field_10;
                    }
                    result = ptr2->field_8;
                    *(__int64 *)((__int64)result + (__int64)i) = dst;
                    i += 4;
                    ptr2->field_10 = i;
                    v9 += 3;
                    *(__int64 *)ptr = (__int64)(v9);
                    return v9;
                }
            }
            result = &off_14011CA48;
            v_20 = (__int64)result;
            a1 = &off_14011CA2C;
            v5 = &off_14011D3F8;
            sub_1400F3B80(a1, 28, str, v5);
            v_58 = v5;
            dst = (__int64 *)str;
            ptr3 = (struct Struct_5_t *)a2;
            ptr2 = (struct Struct_4_t *)a1;
            a1 = *a2;
            i = a2[2];
            a1 = (size_t *)((__int64)a1 - (__int64)i);
            result = (struct Struct_1_t *)i;
            if (a1 <= 6) JUMPOUT(0x1400dcdea);
            a1 = ptr3->field_8;
            *(__int64 *)((__int64)a1 + (__int64)result + 3) = 0;
            *(__int64 *)((__int64)a1 + (__int64)result) = 0x3D8D4C;
            result += 7;
            ptr3->field_10 = result;
            v6 = *dst;
            result = v6 + 1;
            *dst = result;
            sub_14002EDF0(0, 3);
            if (result == 0) JUMPOUT(0x1400dcda0);
            ptr = (struct Struct_3_t *)result;
            *(__int64 *)result = (__int64)(0x894D);
            result->field_2 = 252;
            result = ptr3->field_0;
            a2 = ptr3->field_10;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            if (result <= 2) JUMPOUT(0x1400dce13);
            result = ptr3->field_8;
            a1 = ptr->field_2;
            *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
            a1 = ptr->field_0;
            *(__int64 *)((__int64)result + (__int64)a2) = a1;
            a2 += 3;
            ptr3->field_10 = a2;
            off_140108030(a1, a2);
            off_140108038(result, 0, ptr);
            result = ptr3->field_0;
            ptr = ptr3->field_10;
            result = (struct Struct_1_t *)((__int64)result - (__int64)ptr);
            a2 = (int *)ptr;
            if (result <= 5) JUMPOUT(0x1400dce39);
            result = ptr3->field_8;
            *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
            *(__int64 *)((__int64)result + (__int64)a2) = 0xBE41;
            a2 += 6;
            ptr3->field_10 = a2;
            result = v6 + 3;
            *dst = result;
            result = ptr3->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            if (result <= 1) JUMPOUT(0x1400dce62);
            result = ptr3->field_8;
            *(__int64 *)((__int64)result + (__int64)a2) = 0xB848;
            a2 += 2;
            ptr3->field_10 = a2;
            result = ptr3->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            if (result <= 7) JUMPOUT(0x1400dce88);
            result = ptr3->field_8;
            a1 = 0x9E3779B97F4A7C15;
            *(__int64 *)((__int64)result + (__int64)a2) = a1;
            a2 += 8;
            ptr3->field_10 = a2;
            result = ptr3->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            if (result <= 1) JUMPOUT(0x1400dceae);
            result = ptr3->field_8;
            *(__int64 *)((__int64)result + (__int64)a2) = 0xBB48;
            a2 += 2;
            ptr3->field_10 = a2;
            result = ptr3->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            if (result <= 7) JUMPOUT(0x1400dced4);
            result = ptr3->field_8;
            a1 = 0xA8014F8F497C4A23;
            *(__int64 *)((__int64)result + (__int64)a2) = a1;
            a2 += 8;
            ptr3->field_10 = a2;
            result = ptr3->field_0;
            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
            v_88 = (__int64)ptr2;
            v_80 = (__int64)i;
            v_78 = (__int64)ptr;
            if (result <= 2) JUMPOUT(0x1400dcefa);
            result = ptr3->field_8;
            *(__int64 *)((__int64)result + (__int64)a2 + 2) = 195;
            *(__int64 *)((__int64)result + (__int64)a2) = 0x3148;
            a2 += 3;
            ptr3->field_10 = a2;
            result = v6 + 6;
            v_28 = (__int64)dst;
            *dst = result;
            v6 += 9;
            v9 = 64;
            dst2 = rsp + 48;
            return sub_1400DB34D();
        }
        return (__int64)dst2;
    }
    return (__int64)result;
}