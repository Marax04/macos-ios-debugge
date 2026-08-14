// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    __int16 field_2; // offset 2
    __int64 field_4; // offset 4
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr3`
struct Struct_4_t {
    __int16 field_0; // offset 0
    char _pad_0[1];
    char field_3; // offset 3
    __int16 field_4; // offset 4
    char _pad_4[1];
    __int64 field_7; // offset 7
};

__int64 sub_14002EDF0();
__int64 sub_1400F2D20();
__int64 sub_1400F3326();
__int64 sub_1400D3B74();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400D34C0(int *a1, int *a2, int a3) {
    int v_20;
    int v_40;
    int v_68;
    int v_70;
    int v10;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    struct Struct_4_t *ptr3;
    struct Struct_1_t *result;
    __int64 v2;
    __int64 *dst;
    __int64 v9;
    __int64 *dst2;
    __int64 v5;

    v10 = a3;
    ptr = (struct Struct_2_t *)a2;
    ptr2 = (struct Struct_3_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        ptr3 = (struct Struct_4_t *)result;
        *(__int64 *)result = (__int64)(0x244C8B48);
        result->field_4 = 56;
        result = ptr2->field_0;
        v2 = ptr2->field_10;
        result -= v2;
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr2, v2, 5, 1);
            v2 = ptr2->field_10;
        }
        dst = ptr2->field_8;
        result = ptr3->field_4;
        *(dst + v2 + 4) = result;
        result = ptr3->field_0;
        *(dst + v2) = result;
        v2 += 5;
        ptr2->field_10 = v2;
        off_140108030();
        off_140108038(result, 0, ptr3);
        v9 = ptr->field_0;
        sub_14002EDF0(0, 8);
        if (result != 0) {
            ptr3 = (struct Struct_4_t *)result;
            *(__int64 *)result = (__int64)(0x24548B48);
            result->field_4 = 64;
            result = ptr2->field_0;
            result -= v2;
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr2, v2, 5, 1);
                dst = ptr2->field_8;
                v2 = ptr2->field_10;
            }
            result = ptr3->field_4;
            *(dst + v2 + 4) = result;
            result = ptr3->field_0;
            *(dst + v2) = result;
            v2 += 5;
            ptr2->field_10 = v2;
            off_140108030();
            off_140108038(result, 0, ptr3);
            result = v9 + 2;
            *(__int64 *)ptr = (__int64)(result);
            sub_14002EDF0(0, 6);
            if (result != 0) {
                ptr3 = (struct Struct_4_t *)result;
                *(__int64 *)result = (__int64)(0xB841);
                result->field_2 = v10;
                result = ptr2->field_0;
                result -= v2;
                if (result <= 5) {
                    v_20 = 1;
                    sub_1400F2D20(ptr2, v2, 6, 1);
                    dst = ptr2->field_8;
                    v2 = ptr2->field_10;
                }
                result = ptr3->field_4;
                *(dst + v2 + 4) = result;
                result = ptr3->field_0;
                *(dst + v2) = result;
                v2 += 6;
                ptr2->field_10 = v2;
                off_140108030();
                off_140108038(result, 0, ptr3);
                sub_14002EDF0(0, 8);
                if (result != 0) {
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x244C8D4C);
                    result->field_4 = 48;
                    result = ptr2->field_0;
                    result -= v2;
                    if (result <= 4) {
                        v_20 = 1;
                        sub_1400F2D20(ptr2, v2, 5, 1);
                        v2 = ptr2->field_10;
                    }
                    dst2 = ptr2->field_8;
                    result = ptr3->field_4;
                    *(dst2 + v2 + 4) = result;
                    result = ptr3->field_0;
                    *(dst2 + v2) = result;
                    v2 += 5;
                    ptr2->field_10 = v2;
                    off_140108030();
                    off_140108038(result, 0, ptr3);
                    result = v9 + 4;
                    *(__int64 *)ptr = (__int64)(result);
                    sub_14002EDF0(0, 8);
                    if (result == 0) {
                        sub_1400F3326(1, 8);
                        sub_1400F3326(1, 6);
                    } else {
                        ptr3 = (struct Struct_4_t *)result;
                        *(__int64 *)result = (__int64)(0x24448B48);
                        result->field_4 = 32;
                        result = ptr2->field_0;
                        result -= v2;
                        if (result <= 4) {
                            v_20 = 1;
                            sub_1400F2D20(ptr2, v2, 5, 1);
                            dst2 = ptr2->field_8;
                            v2 = ptr2->field_10;
                        }
                        result = ptr3->field_4;
                        *(dst2 + v2 + 4) = result;
                        result = ptr3->field_0;
                        *(dst2 + v2) = result;
                        v2 += 5;
                        ptr2->field_10 = v2;
                        off_140108030();
                        off_140108038(result, 0, ptr3);
                        sub_14002EDF0(0, 3);
                        if (result != 0) {
                            ptr3 = (struct Struct_4_t *)result;
                            *(__int64 *)result = (__int64)(0xD0FF);
                            result = ptr2->field_0;
                            result -= v2;
                            if (result <= 1) {
                                v_20 = 1;
                                sub_1400F2D20(ptr2, v2, 2, 1);
                                dst2 = ptr2->field_8;
                                v2 = ptr2->field_10;
                            }
                            result = ptr3->field_0;
                            *(dst2 + v2) = result;
                            v2 += 2;
                            ptr2->field_10 = v2;
                            off_140108030();
                            off_140108038(result, 0, ptr3);
                            v9 += 6;
                            *(__int64 *)ptr = (__int64)(v9);
                            return v9;
                        }
                    }
                    sub_1400F3326(1, 3);
                    v_70 = v5;
                    v_68 = a3;
                    v_40 = (int)a2;
                    ptr = (struct Struct_2_t *)a1;
                    sub_14002EDF0(0, 8);
                    if (result == 0) JUMPOUT(0x1400d4e7e);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x24648B4C);
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    ptr3->field_4 = 56;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 4) JUMPOUT(0x1400d4c64);
                    result = ptr->field_8;
                    a1 = ptr3->field_4;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 5;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr3);
                    a1 = (int *)v_40;
                    v2 = *a1;
                    result = v2 + 1;
                    *a1 = result;
                    sub_14002EDF0(0, 8);
                    if (result == 0) JUMPOUT(0x1400d4e7e);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x246C8B4C);
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    ptr3->field_4 = 64;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 4) JUMPOUT(0x1400d4c8a);
                    result = ptr->field_8;
                    a1 = ptr3->field_4;
                    *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 5;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr3);
                    result = v2 + 2;
                    a1 = (int *)v_40;
                    *a1 = result;
                    sub_14002EDF0(0, 11);
                    if (result == 0) JUMPOUT(0x1400d4e8d);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x84C7);
                    result->field_2 = 36;
                    result = 0x6170786500000088;
                    ptr3->field_3 = result;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 10) JUMPOUT(0x1400d4cb0);
                    result = ptr->field_8;
                    a1 = ptr3->field_7;
                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 11;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr3);
                    sub_14002EDF0(0, 11);
                    if (result == 0) JUMPOUT(0x1400d4e8d);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x84C7);
                    result->field_2 = 36;
                    result = 0x3320646E0000008C;
                    ptr3->field_3 = result;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 10) JUMPOUT(0x1400d4cd6);
                    result = ptr->field_8;
                    a1 = ptr3->field_7;
                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 11;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr3);
                    result = v2 + 4;
                    a1 = (int *)v_40;
                    *a1 = result;
                    sub_14002EDF0(0, 11);
                    if (result == 0) JUMPOUT(0x1400d4e8d);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x84C7);
                    result->field_2 = 36;
                    result = 0x79622D3200000090;
                    ptr3->field_3 = result;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 10) JUMPOUT(0x1400d4cfc);
                    result = ptr->field_8;
                    a1 = ptr3->field_7;
                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 11;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr3);
                    sub_14002EDF0(0, 11);
                    if (result == 0) JUMPOUT(0x1400d4e8d);
                    ptr3 = (struct Struct_4_t *)result;
                    *(__int64 *)result = (__int64)(0x84C7);
                    result->field_2 = 36;
                    result = 0x6B20657400000094;
                    ptr3->field_3 = result;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (struct Struct_1_t *)((__int64)result - (__int64)a2);
                    if (result <= 10) JUMPOUT(0x1400d4d22);
                    result = ptr->field_8;
                    a1 = ptr3->field_7;
                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                    a1 = ptr3->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 11;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    ptr2 = 0;
                    off_140108038(result, 0, ptr3);
                    a1 = (int *)v_68;
                    result = a1 + 32;
                    v9 = 0xCBF29CE4;
                    return sub_1400D3B74();
                }
                return v9;
            }
            return v9;
        }
    }
    return (__int64)result;
}