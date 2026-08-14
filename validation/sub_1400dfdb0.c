// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[21];
    __int64 field_2D; // offset 45
    char _pad_2D[249];
    __int64 field_12E; // offset 302
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400F3510();
__int64 sub_1400D4F50();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3B80();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;
extern __int64 off_14011CDE8;
extern __int64 off_14011CDD8;
extern __int64 off_14011D3F8;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;

__int64 __fastcall sub_1400DFDB0(size_t *a1, size_t *a2, int *a3, int a4) {
    __int64 rsp;
    int arg_2;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 v6;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 i;
    __int64 v8;
    __int64 *dst2;
    __int64 v10;
    struct Struct_2_t *ptr2;
    __int64 v5;

    v6 = a4;
    dst = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    i = a1[2];
    if (result == i) {
        do {
            v_20 = 1;
            v8 = (__int64)dst;
            dst = (__int64 *)a3;
            sub_1400F2D20(ptr, i, 1, 1);
            a3 = (int *)dst;
            dst = (__int64 *)v8;
            result = ptr->field_0;
            i = ptr->field_10;
        } while (true);
    }
    dst2 = ptr->field_8;
    *(dst2 + i) = 61;
    ++i;
    ptr->field_10 = i;
    result -= i;
    if (result <= 3) {
        v_20 = 1;
        v8 = (__int64)dst;
        dst = (__int64 *)a3;
        sub_1400F2D20(ptr, i, 4, 1);
        a3 = (int *)dst;
        dst = (__int64 *)v8;
        dst2 = ptr->field_8;
        i = ptr->field_10;
    }
    *(dst2 + i) = a3;
    v8 = i + 4;
    ptr->field_10 = v8;
    v10 = *dst;
    sub_14002EDF0(0, 6);
    if (result != 0) {
        ptr2 = (struct Struct_2_t *)result;
        *result = 0x850F;
        arg_2 = 0;
        result = ptr->field_0;
        result -= v8;
        if (result <= 5) {
            v_20 = 1;
            sub_1400F2D20(ptr, v8, 6, 1);
            dst2 = ptr->field_8;
            v8 = ptr->field_10;
        }
        result = ptr2->field_4;
        *(dst2 + v8 + 4) = result;
        result = ptr2->field_0;
        *(dst2 + v8) = result;
        v8 += 6;
        ptr->field_10 = v8;
        off_140108030();
        off_140108038(result, 0, ptr2);
        result = ptr->field_0;
        a1 = (size_t *)result;
        a1 -= v8;
        if (a1 <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr, v8, 5, 1);
            result = ptr->field_0;
            v8 = ptr->field_10;
        }
        a1 = ptr->field_8;
        *(a1 + v8 + 4) = 111;
        *(a1 + v8) = 0xCB70F4A;
        v8 += 5;
        ptr->field_10 = v8;
        a2 = v10 + 3;
        *dst = a2;
        a2 = (size_t *)result;
        a2 -= v8;
        if (a2 <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr, v8, 4, 1);
            v8 = ptr->field_10;
            result = ptr->field_0;
            a1 = ptr->field_8;
        }
        *(a1 + v8) = 0x8E148B41;
        a2 = v8 + 4;
        ptr->field_10 = a2;
        if (a2 == result) {
            sub_1400F3510(ptr, a2);
            a1 = ptr->field_8;
        }
        *(a1 + v8 + 4) = 76;
        a1 = v8 + 5;
        ptr->field_10 = a1;
        result = ptr->field_0;
        if (a1 == result) {
            sub_1400F3510(ptr);
            result = ptr->field_0;
        }
        ptr2 = ptr->field_8;
        *(__int64 *)(ptr2 + v8 + 5) = (__int64)(1);
        a1 = v8 + 6;
        ptr->field_10 = a1;
        if (a1 == result) {
            sub_1400F3510(ptr);
            ptr2 = ptr->field_8;
        }
        *(__int64 *)(ptr2 + v8 + 6) = (__int64)(226);
        v8 += 7;
        ptr->field_10 = v8;
        result = v10 + 5;
        v_40 = (__int64)dst;
        *dst = result;
        sub_14002EDF0(0, 8);
        if (result != 0) {
            v_28 = 8;
            v_30 = (__int64)result;
            *result = 0x8948;
            v_38 = 2;
            a1 = rsp + 40;
            sub_1400D4F50(a1, 2, 4, v6);
            dst = (__int64 *)v_28;
            v6 = v_30;
            v5 = v_38;
            result = ptr->field_0;
            result -= v8;
            if (v5 > result) {
                v_20 = 1;
                sub_1400F2D20(ptr, v8, v5, 1);
                ptr2 = ptr->field_8;
                v8 = ptr->field_10;
            }
            ptr2 += v8;
            sub_1400F27F0(ptr2, v6, v5);
            v8 += v5;
            ptr->field_10 = v8;
            if (dst == 0) {
                v10 += 6;
                result = (__int64 *)v_40;
                *result = v10;
                a2 = (size_t *)i;
                a2 += 10;
                if (!((a2 < 0))) {
                    result = (__int64 *)v8;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    a1 = (size_t *)result;
                    if (result == result) {
                        if (v8 < a2) {
                            i += 6;
                            a4 = &off_14011D380;
                            sub_1400F3600(i, a2, v8, a4);
                        }
                        a1 = ptr->field_8;
                        *(a1 + i + 6) = result;
                        return (__int64)a1;
                    }
                    result = &off_14011CDE8;
                    v_20 = (__int64)result;
                    a1 = &off_14011CDD8;
                    a4 = &off_14011D3F8;
                    a3 = rsp + 40;
                    sub_1400F3B80(a1, 14, a3, a4);
                    result = (__int64 *)a3;
                    ptr = (struct Struct_1_t *)a1;
                    v_28 = 0;
                    a1 = (size_t *)result;
                    if (((__int64)a1 & 248) != 0) JUMPOUT(0x1400e02dd);
                    *(__int64 *)(rsp + a1 + 40) = 0;
                    a1 = (size_t *)result;
                    if (((__int64)result & 0xF800) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 16);
                    *(__int64 *)(rsp + a1 + 40) = 1;
                    a1 = (size_t *)a3;
                    if (((__int64)result & 0xF80000) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 24);
                    *(__int64 *)(rsp + a1 + 40) = 2;
                    a1 = (size_t *)a3;
                    if (((__int64)result & 0xF8000000) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 32);
                    *(__int64 *)(rsp + a1 + 40) = 3;
                    a1 = (size_t *)a3;
                    a3 = 0xF800000000;
                    if (((__int64)result & (__int64)a3) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 40);
                    *(__int64 *)(rsp + a1 + 40) = 4;
                    a1 = (size_t *)a3;
                    a3 = 0xF80000000000;
                    if (((__int64)result & (__int64)a3) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 48);
                    *(__int64 *)(rsp + a1 + 40) = 5;
                    a1 = (size_t *)a3;
                    a3 = 0xF8000000000000;
                    if (((__int64)result & (__int64)a3) != 0) JUMPOUT(0x1400e02dd);
                    a3 = (int *)result;
                    a3 = (int *)((__int64)(__int64)a3 >> 56);
                    *(__int64 *)(rsp + a1 + 40) = 6;
                    result = (__int64 *)((__int64)(__int64)result >> 59);
                    if ((result != 0)) JUMPOUT(0x1400e02da);
                    *(__int64 *)(rsp + a3 + 40) = 7;
                    a1 = ptr + 46;
                    sub_1400F27F0(a1, a2, 256);
                    result = (__int64 *)v_28;
                    ptr->field_12E = result;
                    *(__int64 *)ptr = (__int64)(0);
                    ptr->field_2D = 0;
                    return (__int64)result;
                }
                result = &off_14011B3E0;
                v_20 = (__int64)result;
                a1 = &off_14011B3C3;
                a4 = &off_14011D3F8;
                a3 = rsp + 40;
                sub_1400F3B80(a1, 23, a3, a4);
                return (__int64)a3;
            }
            off_140108030();
            off_140108038(result, 0, v6);
            return (__int64)a3;
        }
        sub_1400F3326(1, 8);
        return (__int64)a3;
    }
    sub_1400F3326(1, 6);
    return (__int64)result;
}