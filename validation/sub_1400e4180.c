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

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_1400F3B80();
__int64 sub_14002EDF0();
__int64 sub_1400D5BD0();
__int64 sub_1400F27F0();
__int64 off_140108030();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011BCC0;
extern __int64 off_14011BCB0;
extern __int64 off_140108038;

__int64 __fastcall sub_1400E4180(__int64 *a1, int *a2, size_t a3) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    struct Struct_2_t *ptr2;
    __int64 v5;
    struct Struct_3_t *ptr3;
    __int64 *result;
    __int64 v8;
    int v10;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v7;
    __int64 v9;

    ptr2 = (struct Struct_2_t *)a2;
    v5 = *a1;
    ptr3 = a1[2];
    result = (__int64 *)v5;
    result = (__int64 *)((__int64)result - (__int64)ptr3);
    a2 = 0xC6FF49371CB60F43;
    v8 = 0xC6FF493704B60F43;
    if (a3 != 0) v8 = a2;
    if (result <= 7) {
        v_20 = 1;
        v10 = a3;
        ptr = (struct Struct_1_t *)a1;
        sub_1400F2D20(a1, ptr3, 8, 1);
        a3 = v10;
        v5 = ptr->field_0;
        ptr3 = ptr->field_10;
    }
    result = (__int64 *)arg_8;
    *(__int64 *)((__int64)result + (__int64)ptr3) = v8;
    a2 = ptr3 + 8;
    a1[2] = a2;
    v5 -= (__int64)a2;
    if (v5 <= 2) {
        v_20 = 1;
        v10 = a3;
        ptr = (struct Struct_1_t *)a1;
        sub_1400F2D20(ptr, a2, 3, 1);
        a3 = v10;
        result = ptr->field_8;
        a2 = ptr->field_10;
    }
    *(__int64 *)((__int64)result + (__int64)a2 + 2) = 45;
    *(__int64 *)((__int64)result + (__int64)a2) = 0x8D48;
    a2 += 3;
    a1[2] = a2;
    if (ptr2 >= 0) {
        ptr3 += 15;
        if ((ptr3 < 0)) {
            result = &off_14011B3E0;
            v_20 = (__int64)result;
            a1 = &off_14011B3C3;
            v5 = &off_14011D3F8;
            a3 = rsp + 47;
            sub_1400F3B80(a1, 23, a3, v5);
        } else {
            ptr2 = (struct Struct_2_t *)((__int64)ptr2 - (__int64)ptr3);
            v5 = (__int64)ptr2;
            if (ptr2 == ptr2) {
                v5 = *a1;
                v5 -= (__int64)a2;
                if (v5 <= 3) {
                    v_20 = 1;
                    ptr = (struct Struct_1_t *)a3;
                    ptr3 = (struct Struct_3_t *)a1;
                    sub_1400F2D20(ptr, a2, 4, 1);
                    a3 = (size_t)ptr;
                    result = ptr3->field_8;
                    a2 = ptr3->field_10;
                }
                *(__int64 *)((__int64)result + (__int64)a2) = ptr2;
                a2 += 4;
                a1[2] = a2;
                if (a3 == 0) {
                    a3 = *a1;
                    a3 -= (__int64)a2;
                    if (a3 <= 4) {
                        v_20 = 1;
                        ptr2 = (struct Struct_2_t *)a1;
                        sub_1400F2D20(ptr2, a2, 5, 1);
                        a1 = (__int64 *)ptr2;
                        result = ptr2->field_8;
                        a2 = ptr2->field_10;
                    }
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x544B60F;
                } else {
                    a3 = *a1;
                    a3 -= (__int64)a2;
                    if (a3 <= 4) {
                        v_20 = 1;
                        ptr2 = (struct Struct_2_t *)a1;
                        sub_1400F2D20(ptr3, a2, 5, 1);
                        result = ptr2->field_8;
                        a2 = ptr2->field_10;
                    }
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
                    *(__int64 *)((__int64)result + (__int64)a2) = 0x1D5CB60F;
                }
                a2 += 5;
                a1[2] = a2;
                return (__int64)a2;
            }
        }
        result = &off_14011BCC0;
        v_20 = (__int64)result;
        a1 = &off_14011BCB0;
        v5 = &off_14011D3F8;
        a3 = rsp + 47;
        sub_1400F3B80(a1, 16, a3, v5);
        v10 = a3;
        ptr = (struct Struct_1_t *)a2;
        ptr2 = (struct Struct_2_t *)a1;
        result = *a1;
        ptr3 = a1[2];
        result = (__int64 *)((__int64)result - (__int64)ptr3);
        if (result <= 2) JUMPOUT(0x1400e44c4);
        dst = ptr2->field_8;
        *(__int64 *)((__int64)dst + (__int64)ptr3 + 2) = 205;
        *(__int64 *)((__int64)dst + (__int64)ptr3) = 0xFF49;
        ptr3 += 3;
        ptr2->field_10 = ptr3;
        sub_14002EDF0(0, 8);
        if (result == 0) JUMPOUT(0x1400e4517);
        v_28 = 8;
        v_30 = (__int64)result;
        *result = 0x8B4A;
        v_38 = 2;
        v_20 = v10;
        a1 = rsp + 40;
        sub_1400D5BD0(a1, ptr, 5, 3);
        v7 = v_28;
        ptr = (struct Struct_1_t *)v_30;
        v9 = v_38;
        result = ptr2->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr3);
        if (v9 > result) JUMPOUT(0x1400e44ed);
        dst = (__int64 *)((__int64)dst + (__int64)ptr3);
        sub_1400F27F0(dst, ptr, v9);
        ptr3 += v9;
        ptr2->field_10 = ptr3;
        if (v7 != 0) {
            off_140108030();
            a1 = result;
            a2 = 0;
            a3 = (size_t)ptr;
            JUMPOUT(off_140108038);
        }
        return a3;
    }
    return (__int64)result;
}