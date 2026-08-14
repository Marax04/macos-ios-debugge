// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int64 field_2; // offset 2
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_14002EDF0();
__int64 sub_1400D4F50();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 sub_1400F3B80();
__int64 sub_1400F3600();
__int64 sub_1400F3326();
__int64 sub_1400F3869();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011CEC0;
extern __int64 off_14011CEA8;
extern __int64 off_14011D3F8;
extern __int64 off_14011CEE8;
extern __int64 off_14011CED8;
extern __int64 off_14011CF18;
extern __int64 off_14011CF00;
extern __int64 off_14011CF40;
extern __int64 off_14011CF30;
extern __int64 off_14011D380;
extern __int64 off_14011CF98;
extern __int64 off_14011CF88;
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D368;
extern __int64 off_14011CF70;
extern __int64 off_14011CF58;

__int64 __fastcall sub_1400C45C0(int *a1, int *a2, int *a3, size_t *a4) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_30;
    __int64 v_38;
    int v_40;
    int v_70;
    int v_e0;
    int v_e8;
    struct Struct_2_t *ptr;
    int v11;
    __int64 *i;
    struct Struct_3_t *ptr2;
    __int64 v8;
    struct Struct_4_t *ptr3;
    __int64 v10;
    struct Struct_1_t *result;
    __int64 v7;
    __m128i xmm0;
    __int64 *dst;
    __int64 v6;

    ptr = (struct Struct_2_t *)a4;
    v11 = (int)a3;
    i = (__int64 *)a2;
    ptr2 = (struct Struct_3_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        v_30 = 8;
        v_38 = (__int64)result;
        *(__int64 *)result = (__int64)(0x8D48);
        v_40 = 2;
        a1 = rsp + 48;
        sub_1400D4F50(a1, 6, 4, v11);
        v8 = v_30;
        ptr3 = (struct Struct_4_t *)v_38;
        v10 = v_40;
        result = ptr2->field_0;
        v7 = ptr2->field_10;
        result -= v7;
        if (v10 > result) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr2, v7, v10, 1);
                v7 = ptr2->field_10;
            } while (true);
        }
        a1 = ptr2->field_8;
        a1 += v7;
        sub_1400F27F0(a1, ptr3, v10);
        v7 += v10;
        ptr2->field_10 = v7;
        if (v8 == 0) {
            v7 = *i;
            result = v7 + 1;
            *i = result;
            sub_14002EDF0(0, 8);
            if (result != 0) {
                v_30 = 8;
                v_38 = (__int64)result;
                *(__int64 *)result = (__int64)(0x8D48);
                v_40 = 2;
                a1 = rsp + 48;
                sub_1400D4F50(a1, 7, 4, ptr);
                v8 = v_30;
                ptr = (struct Struct_2_t *)v_38;
                ptr3 = (struct Struct_4_t *)v_40;
                result = ptr2->field_0;
                v10 = ptr2->field_10;
                result -= v10;
                if (ptr3 > result) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, v10, ptr3, 1);
                    v10 = ptr2->field_10;
                }
                a1 = ptr2->field_8;
                a1 += v10;
                sub_1400F27F0(a1, ptr, ptr3);
                v10 += (__int64)ptr3;
                ptr2->field_10 = v10;
                if (v8 == 0) {
                    result = v7 + 2;
                    *i = result;
                    sub_14002EDF0(0, 3);
                    if (result == 0) {
                        sub_1400F3340(1, 3);
                        v_20 = 1;
                        sub_1400F2D20(ptr2, a2, 3, 1);
                        a2 = ptr2->field_10;
                        result = ptr2->field_8;
                        a1 = ptr->field_2;
                        *(__int64 *)((__int64)result + (__int64)a2 + 2) = a1;
                        a1 = ptr->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 3;
                        ptr2->field_10 = a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, ptr);
                        result = v7 + 3;
                        *i = result;
                        v8 = ptr2->field_10;
                        sub_14002EDF0(0, 7);
                        if (result != 0) {
                            ptr = (struct Struct_2_t *)result;
                            *(__int64 *)result = (__int64)(0x20F98348);
                            result = ptr2->field_0;
                            a2 = ptr2->field_10;
                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                            if (result <= 3) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, a2, 4, 1);
                                a2 = ptr2->field_10;
                            }
                            result = ptr2->field_8;
                            a1 = ptr->field_0;
                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                            a2 += 4;
                            ptr2->field_10 = a2;
                            off_140108030(a1, a2);
                            off_140108038(result, 0, ptr);
                            result = v7 + 4;
                            *i = result;
                            ptr = ptr2->field_10;
                            sub_14002EDF0(0, 6);
                            if (result != 0) {
                                ptr3 = (struct Struct_4_t *)result;
                                *(__int64 *)result = (__int64)(0x840F);
                                result->field_2 = 0;
                                result = ptr2->field_0;
                                a2 = ptr2->field_10;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                if (result <= 5) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, a2, 6, 1);
                                    a2 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                a1 = ptr3->field_4;
                                *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                a1 = ptr3->field_0;
                                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                a2 += 6;
                                ptr2->field_10 = a2;
                                off_140108030(a1, a2);
                                off_140108038(result, 0, ptr3);
                                result = v7 + 5;
                                *i = result;
                                result = ptr2->field_0;
                                ptr3 = ptr2->field_10;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                if (result <= 2) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, ptr3, 3, 1);
                                    ptr3 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)((__int64)result + (__int64)ptr3 + 2) = 78;
                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x48A;
                                ptr3 += 3;
                                ptr2->field_10 = ptr3;
                                result = ptr2->field_0;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, ptr3, 2, 1);
                                    ptr3 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x200C;
                                ptr3 += 2;
                                ptr2->field_10 = ptr3;
                                result = ptr2->field_0;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, ptr3, 2, 1);
                                    ptr3 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x393C;
                                v10 = ptr3 + 2;
                                ptr2->field_10 = v10;
                                result = ptr2->field_0;
                                result -= v10;
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, v10, 2, 1);
                                    v10 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)(result + v10) = (__int64)(118);
                                v10 += 2;
                                ptr2->field_10 = v10;
                                result = v7 + 9;
                                *i = result;
                                result = ptr2->field_0;
                                result -= v10;
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, v10, 2, 1);
                                    v10 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)(result + v10) = (__int64)(0x572C);
                                a2 = v10 + 2;
                                ptr2->field_10 = a2;
                                result = ptr2->field_0;
                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                if (result <= 1) {
                                    v_20 = 1;
                                    sub_1400F2D20(ptr2, a2, 2, 1);
                                    a2 = ptr2->field_10;
                                }
                                result = ptr2->field_8;
                                *(__int64 *)((__int64)result + (__int64)a2) = 235;
                                a2 += 2;
                                ptr2->field_10 = a2;
                                a1 = (int *)ptr3;
                                a1 += 4;
                                if (!((a1 < 0))) {
                                    result = (struct Struct_1_t *)a2;
                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                    a1 = (int *)result;
                                    if (result != result) {
                                        result = &off_14011CEC0;
                                        v_20 = (__int64)result;
                                        a1 = &off_14011CEA8;
                                        a4 = &off_14011D3F8;
                                        a3 = rsp + 48;
                                        sub_1400F3B80(a1, 17, a3, a4);
                                        v_20 = 1;
                                        sub_1400F2D20(ptr2, a2, 2, 1);
                                        a2 = ptr2->field_10;
                                        result = ptr2->field_8;
                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x302C;
                                        a2 += 2;
                                        ptr2->field_10 = a2;
                                        result = v7 + 12;
                                        *i = result;
                                        a1 = (int *)v10;
                                        a1 += 4;
                                        if (!((a1 < 0))) {
                                            result = (struct Struct_1_t *)a2;
                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                            a1 = (int *)result;
                                            if (result != result) {
                                                result = &off_14011CEE8;
                                                v_20 = (__int64)result;
                                                a1 = &off_14011CED8;
                                                a4 = &off_14011D3F8;
                                                a3 = rsp + 48;
                                                sub_1400F3B80(a1, 16, a3, a4);
                                                v_20 = 1;
                                                sub_1400F2D20(ptr2, ptr3, 3, 1);
                                                ptr3 = ptr2->field_10;
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr3 + 2) = 4;
                                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0xE0C0;
                                                ptr3 += 3;
                                                ptr2->field_10 = ptr3;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, ptr3, 2, 1);
                                                    ptr3 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0xC288;
                                                ptr3 += 2;
                                                ptr2->field_10 = ptr3;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                if (result <= 3) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, ptr3, 4, 1);
                                                    ptr3 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x14E448A;
                                                ptr3 += 4;
                                                ptr2->field_10 = ptr3;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, ptr3, 2, 1);
                                                    ptr3 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x200C;
                                                ptr3 += 2;
                                                ptr2->field_10 = ptr3;
                                                result = v7 + 16;
                                                *i = result;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, ptr3, 2, 1);
                                                    ptr3 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)ptr3) = 0x393C;
                                                v10 = ptr3 + 2;
                                                ptr2->field_10 = v10;
                                                result = ptr2->field_0;
                                                result -= v10;
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, v10, 2, 1);
                                                    v10 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)(result + v10) = (__int64)(118);
                                                v10 += 2;
                                                ptr2->field_10 = v10;
                                                result = ptr2->field_0;
                                                result -= v10;
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, v10, 2, 1);
                                                    v10 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)(result + v10) = (__int64)(0x572C);
                                                a2 = v10 + 2;
                                                ptr2->field_10 = a2;
                                                result = ptr2->field_0;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                if (result <= 1) {
                                                    v_20 = 1;
                                                    sub_1400F2D20(ptr2, a2, 2, 1);
                                                    a2 = ptr2->field_10;
                                                }
                                                result = ptr2->field_8;
                                                *(__int64 *)((__int64)result + (__int64)a2) = 235;
                                                a2 += 2;
                                                ptr2->field_10 = a2;
                                                a1 = (int *)ptr3;
                                                a1 += 4;
                                                if (!((a1 < 0))) {
                                                    result = (struct Struct_1_t *)a2;
                                                    result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                                    a1 = (int *)result;
                                                    if (result != result) {
                                                        result = &off_14011CF18;
                                                        v_20 = (__int64)result;
                                                        a1 = &off_14011CF00;
                                                        a4 = &off_14011D3F8;
                                                        a3 = rsp + 48;
                                                        sub_1400F3B80(a1, 17, a3, a4);
                                                        v_20 = 1;
                                                        sub_1400F2D20(ptr2, a2, 2, 1);
                                                        a2 = ptr2->field_10;
                                                        result = ptr2->field_8;
                                                        *(__int64 *)((__int64)result + (__int64)a2) = 0x302C;
                                                        a2 += 2;
                                                        ptr2->field_10 = a2;
                                                        a1 = (int *)v10;
                                                        a1 += 4;
                                                        if (!((a1 < 0))) {
                                                            result = (struct Struct_1_t *)a2;
                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a1);
                                                            a1 = (int *)result;
                                                            if (result != result) {
                                                                result = &off_14011CF40;
                                                                v_20 = (__int64)result;
                                                                a1 = &off_14011CF30;
                                                                a4 = &off_14011D3F8;
                                                                a3 = rsp + 48;
                                                                sub_1400F3B80(a1, 16, a3, a4);
                                                                v_20 = 1;
                                                                sub_1400F2D20(ptr2, a2, 2, 1);
                                                                a2 = ptr2->field_10;
                                                                result = ptr2->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xD008;
                                                                a2 += 2;
                                                                ptr2->field_10 = a2;
                                                                result = v7 + 22;
                                                                *i = result;
                                                                result = ptr2->field_0;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                    a2 = ptr2->field_10;
                                                                }
                                                                result = ptr2->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 15;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0x488;
                                                                a2 += 3;
                                                                ptr2->field_10 = a2;
                                                                result = ptr2->field_0;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                if (result <= 2) {
                                                                    v_20 = 1;
                                                                    sub_1400F2D20(ptr2, a2, 3, 1);
                                                                    a2 = ptr2->field_10;
                                                                }
                                                                result = ptr2->field_8;
                                                                *(__int64 *)((__int64)result + (__int64)a2 + 2) = 193;
                                                                *(__int64 *)((__int64)result + (__int64)a2) = 0xFF48;
                                                                result = a2 + 3;
                                                                ptr2->field_10 = result;
                                                                a2 += 8;
                                                                if (!((a2 < 0))) {
                                                                    v8 -= (__int64)a2;
                                                                    result = (struct Struct_1_t *)v8;
                                                                    if (v8 == v8) {
                                                                        sub_14002EDF0(0, 5);
                                                                        if (result != 0) {
                                                                            ptr3 = (struct Struct_4_t *)result;
                                                                            *(__int64 *)result = (__int64)(233);
                                                                            result->field_1 = v8;
                                                                            result = ptr2->field_0;
                                                                            a2 = ptr2->field_10;
                                                                            result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                            if (result <= 4) {
                                                                                v_20 = 1;
                                                                                sub_1400F2D20(ptr2, a2, 5, 1);
                                                                                a2 = ptr2->field_10;
                                                                            }
                                                                            result = ptr2->field_8;
                                                                            a1 = ptr3->field_4;
                                                                            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                                                                            a1 = ptr3->field_0;
                                                                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                                                                            a2 += 5;
                                                                            ptr2->field_10 = a2;
                                                                            off_140108030(a1, a2);
                                                                            off_140108038(result, 0, ptr3);
                                                                            v7 += 25;
                                                                            *i = v7;
                                                                            a2 = (int *)ptr;
                                                                            a2 += 6;
                                                                            if (!((a2 < 0))) {
                                                                                a3 = ptr2->field_10;
                                                                                result = (struct Struct_1_t *)a3;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                                a1 = (int *)result;
                                                                                if (result == result) {
                                                                                    if (a3 < a2) {
                                                                                        ptr += 2;
                                                                                        a4 = &off_14011D380;
                                                                                        sub_1400F3600(ptr, a2, a3, a4);
                                                                                    }
                                                                                    a1 = ptr2->field_8;
                                                                                    *(__int64 *)((__int64)a1 + (__int64)ptr + 2) = result;
                                                                                    return (__int64)a1;
                                                                                }
                                                                                result = &off_14011CF98;
                                                                                v_20 = (__int64)result;
                                                                                a1 = &off_14011CF88;
                                                                                a4 = &off_14011D3F8;
                                                                                a3 = rsp + 48;
                                                                                sub_1400F3B80(a1, 12, a3, a4);
                                                                                xmm0 = _mm_loadu_si128((__m128i *)&v_e8);
                                                                                _mm_storeu_si128((__m128i *)&v_70, xmm0);
                                                                                result = *a1;
                                                                                i = a1[2];
                                                                                dst = (__int64 *)result;
                                                                                dst = (__int64 *)((__int64)dst - (__int64)i);
                                                                                if (dst <= 1) JUMPOUT(0x1400c5518);
                                                                                dst = (__int64 *)arg_8;
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = 0x310F;
                                                                                i += 2;
                                                                                a1[2] = i;
                                                                                ptr3 = *a2;
                                                                                v6 = (__int64)result;
                                                                                v6 -= (__int64)i;
                                                                                if (v6 <= 3) JUMPOUT(0x1400c5559);
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = 0x20E2C148;
                                                                                i += 4;
                                                                                a1[2] = i;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                if (result <= 2) JUMPOUT(0x1400c559e);
                                                                                *(__int64 *)((__int64)dst + (__int64)i + 2) = 208;
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = 0x948;
                                                                                i += 3;
                                                                                a1[2] = i;
                                                                                result = *a1;
                                                                                dst = (__int64 *)result;
                                                                                dst = (__int64 *)((__int64)dst - (__int64)i);
                                                                                if (dst <= 2) JUMPOUT(0x1400c55e0);
                                                                                dst = (__int64 *)arg_8;
                                                                                *(__int64 *)((__int64)dst + (__int64)i + 2) = 195;
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = 0x8949;
                                                                                i += 3;
                                                                                a1[2] = i;
                                                                                v6 = ptr3 + 4;
                                                                                *a2 = v6;
                                                                                if (result == i) JUMPOUT(0x1400c5621);
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = 185;
                                                                                ++i;
                                                                                a1[2] = i;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)i);
                                                                                if (result <= 3) JUMPOUT(0x1400c5666);
                                                                                *(__int64 *)((__int64)dst + (__int64)i) = a4;
                                                                                result = i + 4;
                                                                                a1[2] = result;
                                                                                a4 = *a1;
                                                                                a4 = (size_t *)((__int64)a4 - (__int64)result);
                                                                                if (a4 <= 1) JUMPOUT(0x1400c56a8);
                                                                                a4 = (size_t *)arg_8;
                                                                                *(__int64 *)((__int64)a4 + (__int64)result) = 0xC9FF;
                                                                                ptr2 = result + 2;
                                                                                a1[2] = ptr2;
                                                                                dst = (__int64 *)result;
                                                                                dst += 4;
                                                                                if ((dst < 0)) JUMPOUT(0x1400c5957);
                                                                                i = (__int64 *)((__int64)i - (__int64)result);
                                                                                result = (struct Struct_1_t *)i;
                                                                                if (i != i) JUMPOUT(0x1400c56e0);
                                                                                result = *a1;
                                                                                dst = (__int64 *)result;
                                                                                dst = (__int64 *)((__int64)dst - (__int64)ptr2);
                                                                                if (dst <= 1) JUMPOUT(0x1400c5738);
                                                                                i = (__int64 *)((__int64)(__int64)i << 8);
                                                                                i = (__int64 *)((__int64)(__int64)i | 117);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = i;
                                                                                ptr2 += 2;
                                                                                a1[2] = ptr2;
                                                                                dst = ptr3 + 7;
                                                                                *a2 = dst;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                if (result <= 1) JUMPOUT(0x1400c5777);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x310F;
                                                                                ptr2 += 2;
                                                                                a1[2] = ptr2;
                                                                                result = *a1;
                                                                                a4 = (size_t *)result;
                                                                                a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
                                                                                if (a4 <= 3) JUMPOUT(0x1400c57b3);
                                                                                a4 = (size_t *)arg_8;
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x20E2C148;
                                                                                ptr2 += 4;
                                                                                a1[2] = ptr2;
                                                                                dst = (__int64 *)result;
                                                                                dst = (__int64 *)((__int64)dst - (__int64)ptr2);
                                                                                if (dst <= 2) JUMPOUT(0x1400c57ee);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 208;
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x948;
                                                                                ptr2 += 3;
                                                                                a1[2] = ptr2;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                if (result <= 2) JUMPOUT(0x1400c582d);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 216;
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x294C;
                                                                                ptr2 += 3;
                                                                                a1[2] = ptr2;
                                                                                result = ptr3 + 11;
                                                                                *a2 = result;
                                                                                result = *a1;
                                                                                a4 = (size_t *)result;
                                                                                a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
                                                                                if (a4 <= 1) JUMPOUT(0x1400c5869);
                                                                                ptr = (struct Struct_2_t *)v_e0;
                                                                                a4 = (size_t *)arg_8;
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0xB948;
                                                                                ptr2 += 2;
                                                                                a1[2] = ptr2;
                                                                                dst = (__int64 *)result;
                                                                                dst = (__int64 *)((__int64)dst - (__int64)ptr2);
                                                                                if (dst <= 7) JUMPOUT(0x1400c58a4);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = ptr;
                                                                                ptr2 += 8;
                                                                                a1[2] = ptr2;
                                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr2);
                                                                                if (result <= 2) JUMPOUT(0x1400c58e3);
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2 + 2) = 200;
                                                                                *(__int64 *)((__int64)a4 + (__int64)ptr2) = 0x3948;
                                                                                ptr2 += 3;
                                                                                a1[2] = ptr2;
                                                                                a4 = *a1;
                                                                                a4 = (size_t *)((__int64)a4 - (__int64)ptr2);
                                                                                result = (struct Struct_1_t *)ptr2;
                                                                                if (a4 <= 5) JUMPOUT(0x1400c591f);
                                                                                a4 = (size_t *)arg_8;
                                                                                *(__int64 *)((__int64)a4 + (__int64)result + 4) = 0;
                                                                                *(__int64 *)((__int64)a4 + (__int64)result) = 0x870F;
                                                                                result += 6;
                                                                                a1[2] = result;
                                                                                ptr3 += 14;
                                                                                *a2 = ptr3;
                                                                                i = a3[2];
                                                                                if (i == *a3) JUMPOUT(0x1400c5508);
                                                                                result = (struct Struct_1_t *)arg_8;
                                                                                ((__int64 *)result)[(__int64)i] = (__int64)(ptr2);
                                                                                ++i;
                                                                                a3[2] = i;
                                                                                return (__int64)i;
                                                                            }
                                                                            result = &off_14011B3E0;
                                                                            v_20 = (__int64)result;
                                                                            a1 = &off_14011B3C3;
                                                                            a4 = &off_14011D3F8;
                                                                            a3 = rsp + 48;
                                                                            sub_1400F3B80(a1, 23, a3, a4);
                                                                            sub_1400F3326(1, 8);
                                                                            a3 = &off_14011D368;
                                                                            sub_1400F3869(ptr3, a2, a3);
                                                                            a3 = &off_14011D368;
                                                                            sub_1400F3869(v10, a2, a3);
                                                                            sub_1400F3326(1, 7);
                                                                            sub_1400F3326(1, 6);
                                                                            result = &off_14011CF70;
                                                                            v_20 = (__int64)result;
                                                                            a1 = &off_14011CF58;
                                                                            a4 = &off_14011D3F8;
                                                                            a3 = rsp + 48;
                                                                            sub_1400F3B80(a1, 17, a3, a4);
                                                                        }
                                                                        sub_1400F3326(1, 5);
                                                                        return (__int64)a3;
                                                                    }
                                                                    return (__int64)a3;
                                                                }
                                                                return (__int64)a3;
                                                            }
                                                            v10 += 3;
                                                            if (v10 < a2) {
                                                                a1 = ptr2->field_8;
                                                                *(a1 + v10) = result;
                                                                result = ptr2->field_0;
                                                                a2 = ptr2->field_10;
                                                                result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                                if (result <= 1) {
                                                                    return (__int64)result;
                                                                }
                                                                return (__int64)result;
                                                            }
                                                            return (__int64)result;
                                                        }
                                                        return (__int64)result;
                                                    }
                                                    ptr3 += 3;
                                                    if (ptr3 < a2) {
                                                        a1 = ptr2->field_8;
                                                        *(__int64 *)((__int64)a1 + (__int64)ptr3) = result;
                                                        result = ptr2->field_0;
                                                        a2 = ptr2->field_10;
                                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                                        if (result <= 1) {
                                                            return (__int64)result;
                                                        }
                                                        return (__int64)result;
                                                    }
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            v10 += 3;
                                            if (v10 < a2) {
                                                a1 = ptr2->field_8;
                                                *(a1 + v10) = result;
                                                result = ptr2->field_0;
                                                ptr3 = ptr2->field_10;
                                                result = (struct Struct_1_t *)((__int64)result - (__int64)ptr3);
                                                if (result <= 2) {
                                                    return (__int64)result;
                                                }
                                                return (__int64)result;
                                            }
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    ptr3 += 3;
                                    if (ptr3 < a2) {
                                        a1 = ptr2->field_8;
                                        *(__int64 *)((__int64)a1 + (__int64)ptr3) = result;
                                        result = ptr2->field_0;
                                        a2 = ptr2->field_10;
                                        result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                                        if (result <= 1) {
                                            return (__int64)result;
                                        }
                                        return (__int64)result;
                                    }
                                    return (__int64)result;
                                }
                                return (__int64)result;
                            }
                            return (__int64)result;
                        }
                        return (__int64)result;
                    }
                    ptr = (struct Struct_2_t *)result;
                    *(__int64 *)result = (__int64)(0x3148);
                    result->field_2 = 201;
                    result = ptr2->field_0;
                    a2 = ptr2->field_10;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 2) {
                        return (__int64)result;
                    }
                    return (__int64)result;
                }
                off_140108030();
                off_140108038(result, 0, ptr);
                return (__int64)result;
            }
            return (__int64)result;
        }
        off_140108030();
        off_140108038(result, 0, ptr3);
        return (__int64)result;
    }
    return (__int64)result;
}