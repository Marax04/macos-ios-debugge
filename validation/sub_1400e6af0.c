// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 3 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_1400E6900();
__int64 sub_1400FAE80();
__int64 sub_1400F3600();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D380;

__int64 __fastcall sub_1400E6AF0(size_t *a1, int a2) {
    __int64 rsp;
    int v_20;
    int v_30;
    int v_38;
    int v_40;
    int v4;
    struct Struct_3_t *ptr3;
    __int64 *result;
    __int64 v2;
    struct Struct_1_t *ptr;
    int v13;
    struct Struct_2_t *ptr2;
    __int64 v5;
    __int64 *dst;
    __int64 v9;
    __int64 v10;
    __int64 v7;
    __int64 v8;

    v4 = a2;
    ptr3 = (struct Struct_3_t *)a1;
    result = *a1;
    a2 = a1[2];
    result -= a2;
    if (result <= 4) {
        do {
            v_20 = 1;
            sub_1400F2D20(ptr3, a2, 5, 1);
            a2 = ptr3->field_10;
        } while (true);
    }
    result = ptr3->field_8;
    *(result + a2 + 4) = 55;
    *(result + a2) = 0x4B60F43;
    a2 += 5;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, a2, 3, 1);
        a2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + a2 + 2) = 198;
    *(result + a2) = 0xFF49;
    a2 += 3;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, a2, 3, 1);
        a2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + a2 + 2) = 192;
    *(result + a2) = 0x8949;
    a2 += 3;
    ptr3->field_10 = a2;
    sub_1400E6900(ptr3, 3);
    result = ptr3->field_0;
    a2 = ptr3->field_10;
    result -= a2;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, a2, 3, 1);
        a2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + a2 + 2) = 218;
    *(result + a2) = 0x8949;
    a2 += 3;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    a1 = (size_t *)result;
    a1 -= a2;
    if (a1 <= 4) {
        v_20 = 1;
        sub_1400F2D20(ptr3, a2, 5, 1);
        result = ptr3->field_0;
        a2 = ptr3->field_10;
    }
    a1 = ptr3->field_8;
    *(a1 + a2) = 0x846F0FF3;
    *(a1 + a2 + 4) = 28;
    a2 += 5;
    ptr3->field_10 = a2;
    result -= a2;
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, a2, 4, 1);
        a1 = ptr3->field_8;
        a2 = ptr3->field_10;
    }
    *(a1 + a2) = v4;
    a2 += 4;
    ptr3->field_10 = a2;
    sub_1400E6900(ptr3, 1);
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    a1 = (size_t *)result;
    a1 -= v2;
    if (a1 <= 4) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 5, 1);
        result = ptr3->field_0;
        v2 = ptr3->field_10;
    }
    a1 = ptr3->field_8;
    *(a1 + v2) = 0x8C6F0FF3;
    *(a1 + v2 + 4) = 12;
    v2 += 5;
    ptr3->field_10 = v2;
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 4, 1);
        a1 = ptr3->field_8;
        v2 = ptr3->field_10;
    }
    *(a1 + v2) = v4;
    v2 += 4;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 4) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 5, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 4) = 55;
    *(result + v2) = 0x4B60F43;
    v2 += 5;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 3, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 2) = 198;
    *(result + v2) = 0xFF49;
    v2 += 3;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 3, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 2) = 193;
    *(result + v2) = 0x8949;
    v2 += 3;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 4, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2) = 0x30EC8348;
    v2 += 4;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 5) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 6, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 4) = 0x1024;
    *(result + v2) = 0x447F0FF3;
    v2 += 6;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 5) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 6, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 4) = 0x2024;
    *(result + v2) = 0x4C7F0FF3;
    v2 += 6;
    ptr3->field_10 = v2;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 4) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 5, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2 + 4) = 36;
    *(result + v2) = 0xC7F0FF3;
    v2 += 5;
    ptr3->field_10 = v2;
    v_30 = 0;
    v_38 = 8;
    v_40 = 0;
    result = ptr3->field_0;
    result -= v2;
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, v2, 4, 1);
        v2 = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(result + v2) = 0xF88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 6, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 4, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x2014448B;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) {
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 4, 1);
        ptr = ptr3->field_10;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x244489;
    ptr += 4;
    ptr3->field_10 = ptr;
    v13 = 0x4244489;
    ptr2 = 2;
    do {
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = ptr2;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 4, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x2014448B;
        ptr += 4;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 4, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = v13;
        ptr += 4;
        ptr3->field_10 = ptr;
        v13 += 0x4000000;
        ptr2 += 2;
    } while (v13 != 0x10244489);
    a1 = rsp + 48;
    sub_1400FAE80(a1);
    ptr2 = (struct Struct_2_t *)v_38;
    *(__int64 *)ptr2 = (__int64)(ptr);
    v_40 = 1;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e89c8);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e975c);
    if (result < a2) {
        v2 += 6;
        dst = &off_14011D380;
        sub_1400F3600(v2, a2, result, dst);
        dst = &off_14011D380;
        sub_1400F3600(a1, a2, v5, dst);
        ptr2 += 6;
        dst = &off_14011D380;
        sub_1400F3600(ptr2, a2, result, dst);
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    result -= v2;
    if (result <= 3) JUMPOUT(0x1400e89f1);
    result = ptr3->field_8;
    *(result + v2) = 0x1F88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) JUMPOUT(0x1400e8a1a);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8a43);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8a6c);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8a95);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e8abe);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 32;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x1444B70F;
    ptr += 5;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e8ae7);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x24448966;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    ptr += 5;
    ptr3->field_10 = ptr;
    v13 = 2;
    do {
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = v13;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 5, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 4) = 32;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x1444B70F;
        ptr += 5;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 5, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x24448966;
        *(__int64 *)((__int64)result + (__int64)ptr + 4) = v13;
        ptr += 5;
        ptr3->field_10 = ptr;
        v13 += 2;
    } while (v13 != 8);
    if (v_30 == 1) {
        a1 = rsp + 48;
        sub_1400FAE80(a1, a2);
        ptr2 = (struct Struct_2_t *)v_38;
    }
    ptr2->field_8 = ptr;
    v_40 = 2;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e8b10);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e9785);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    result -= v2;
    if (result <= 3) JUMPOUT(0x1400e8b39);
    result = ptr3->field_8;
    *(result + v2) = 0x2F88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) JUMPOUT(0x1400e8b62);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8b8b);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8bb4);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8bdd);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e8c06);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 40;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x1444B70F;
    ptr += 5;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e8c2f);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x24448966;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 8;
    ptr += 5;
    ptr3->field_10 = ptr;
    v9 = 2;
    do {
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        v_20 = 1;
        sub_1400F2D20(ptr3, ptr, 3, 1);
        ptr = ptr3->field_10;
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = v9;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 3, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
        ptr += 3;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 5, 1);
            ptr = ptr3->field_10;
        }
        result = ptr3->field_8;
        *(__int64 *)((__int64)result + (__int64)ptr + 4) = 40;
        *(__int64 *)((__int64)result + (__int64)ptr) = 0x1444B70F;
        ptr += 5;
        ptr3->field_10 = ptr;
        result = ptr3->field_0;
        result = (__int64 *)((__int64)result - (__int64)ptr);
        if (result <= 4) {
            v_20 = 1;
            sub_1400F2D20(ptr3, ptr, 5, 1);
            ptr = ptr3->field_10;
        }
        result = v9 + 8;
        a1 = ptr3->field_8;
        *(__int64 *)((__int64)a1 + (__int64)ptr) = 0x24448966;
        *(__int64 *)((__int64)a1 + (__int64)ptr + 4) = result;
        ptr += 5;
        ptr3->field_10 = ptr;
        v9 += 2;
    } while (v9 != 8);
    if (v_30 == 2) {
        a1 = rsp + 48;
        sub_1400FAE80(a1);
        ptr2 = (struct Struct_2_t *)v_38;
    }
    ptr2->field_10 = ptr;
    v_40 = 3;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e8c58);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e97ae);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    result -= v2;
    if (result <= 3) JUMPOUT(0x1400e8c81);
    result = ptr3->field_8;
    *(result + v2) = 0x3F88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) JUMPOUT(0x1400e8caa);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8cd3);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8cfc);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8d25);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8d4e);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x1014448B;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8d77);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x244489;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8da0);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8dc9);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8df2);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8e1b);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8e44);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x1014448B;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8e6d);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x4244489;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result < 3) JUMPOUT(0x1400e8e96);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8ebf);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 4;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8ee8);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8f11);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8f3a);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x2014448B;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e8f63);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8244489;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8f8c);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8fb5);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 6;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e8fde);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 3;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e9007);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 2;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE2C1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e9030);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x2014448B;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e9059);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xC244489;
    ptr += 4;
    ptr3->field_10 = ptr;
    if (v_30 == 3) {
        a1 = rsp + 48;
        sub_1400FAE80(a1);
        ptr2 = (struct Struct_2_t *)v_38;
    }
    ptr2->field_18 = ptr;
    v_40 = 4;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e9082);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e97d7);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    result -= v2;
    if (result <= 3) JUMPOUT(0x1400e90ab);
    result = ptr3->field_8;
    *(result + v2) = 0x4F88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) JUMPOUT(0x1400e90d4);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e90fd);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e9126);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e914f);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3E2C148;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e9178);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 16;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x14448B48;
    ptr += 5;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e91a1);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x24048948;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e91ca);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 202;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x8944;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e91f3);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xEAC1;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e921c);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 1;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0xE283;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 3) JUMPOUT(0x1400e9245);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3E2C148;
    ptr += 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e926e);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 32;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x14448B48;
    ptr += 5;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 4) JUMPOUT(0x1400e9297);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 8;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x24448948;
    ptr += 5;
    ptr3->field_10 = ptr;
    if (v_30 == 4) {
        a1 = rsp + 48;
        sub_1400FAE80(a1);
        ptr2 = (struct Struct_2_t *)v_38;
    }
    ptr2->field_20 = ptr;
    v_40 = 5;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e92c0);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e9800);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    result = ptr3->field_0;
    v2 = ptr3->field_10;
    result -= v2;
    if (result <= 3) JUMPOUT(0x1400e92e9);
    result = ptr3->field_8;
    *(result + v2) = 0x5F88041;
    ptr = v2 + 4;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 5) JUMPOUT(0x1400e9312);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 4) = 0;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x850F;
    ptr += 6;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    if (result <= 2) JUMPOUT(0x1400e933b);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr + 2) = 201;
    *(__int64 *)((__int64)result + (__int64)ptr) = 0x3148;
    ptr += 3;
    ptr3->field_10 = ptr;
    result = ptr3->field_0;
    result = (__int64 *)((__int64)result - (__int64)ptr);
    ptr2 = (struct Struct_2_t *)ptr;
    if (result <= 3) JUMPOUT(0x1400e9364);
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr2) = 0x10F98348;
    v9 = ptr2 + 4;
    ptr3->field_10 = v9;
    result = ptr3->field_0;
    result -= v9;
    if (result <= 5) JUMPOUT(0x1400e938d);
    result = ptr3->field_8;
    *(result + v9 + 4) = 0;
    *(result + v9) = 0x8D0F;
    v9 += 6;
    ptr3->field_10 = v9;
    result = ptr3->field_0;
    result -= v9;
    if (result <= 2) JUMPOUT(0x1400e93b6);
    result = ptr3->field_8;
    *(result + v9 + 2) = 202;
    *(result + v9) = 0x8948;
    v9 += 3;
    ptr3->field_10 = v9;
    result = ptr3->field_0;
    result -= v9;
    if (result <= 2) JUMPOUT(0x1400e93df);
    result = ptr3->field_8;
    *(result + v9 + 2) = 202;
    *(result + v9) = 332;
    v9 += 3;
    ptr3->field_10 = v9;
    result = ptr3->field_0;
    result -= v9;
    if (result <= 1) JUMPOUT(0x1400e9408);
    result = ptr3->field_8;
    *(result + v9) = 0xC030;
    v9 += 2;
    ptr3->field_10 = v9;
    result = ptr3->field_0;
    result -= v9;
    if (result <= 3) JUMPOUT(0x1400e9431);
    result = ptr3->field_8;
    *(result + v9) = 0x10FA8348;
    v10 = v9 + 4;
    ptr3->field_10 = v10;
    result = ptr3->field_0;
    result -= v10;
    if (result <= 1) JUMPOUT(0x1400e945a);
    result = ptr3->field_8;
    *(result + v10) = 125;
    v10 += 2;
    ptr3->field_10 = v10;
    result = ptr3->field_0;
    result -= v10;
    if (result <= 3) JUMPOUT(0x1400e9483);
    result = ptr3->field_8;
    *(result + v10) = 0x2014448A;
    a2 = v10 + 4;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 1) JUMPOUT(0x1400e94ac);
    result = ptr3->field_8;
    *(result + a2) = 235;
    a2 += 2;
    ptr3->field_10 = a2;
    a1 = (size_t *)v9;
    a1 += 6;
    if ((a1 < 0)) JUMPOUT(0x1400e970a);
    result = (__int64 *)a2;
    result = (__int64 *)((__int64)result - (__int64)a1);
    a1 = (size_t *)result;
    if (result != result) JUMPOUT(0x1400e94d2);
    v9 += 5;
    if (v9 >= a2) JUMPOUT(0x1400e9829);
    a1 = ptr3->field_8;
    *(a1 + v9) = result;
    result = ptr3->field_0;
    v9 = ptr3->field_10;
    result -= v9;
    if (result <= 3) JUMPOUT(0x1400e94de);
    result = ptr3->field_8;
    *(result + v9) = 0x20FA8348;
    a2 = v9 + 4;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 1) JUMPOUT(0x1400e9507);
    result = ptr3->field_8;
    *(result + a2) = 125;
    a2 += 2;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e952d);
    result = ptr3->field_8;
    *(result + a2) = 0xF07A8D48;
    a2 += 4;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e9553);
    result = ptr3->field_8;
    *(result + a2) = 0x103C448A;
    a2 += 4;
    ptr3->field_10 = a2;
    a1 = (size_t *)v10;
    a1 += 6;
    if ((a1 < 0)) JUMPOUT(0x1400e970a);
    result = (__int64 *)a2;
    result = (__int64 *)((__int64)result - (__int64)a1);
    a1 = (size_t *)result;
    if (result != result) JUMPOUT(0x1400e9579);
    v10 += 5;
    if (v10 >= a2) JUMPOUT(0x1400e9838);
    a1 = ptr3->field_8;
    *(a1 + v10) = result;
    result = (__int64 *)v9;
    result += 6;
    if ((result < 0)) JUMPOUT(0x1400e970a);
    a2 -= (__int64)result;
    result = (__int64 *)a2;
    if (a2 != a2) JUMPOUT(0x1400e9582);
    v9 += 5;
    result = ptr3->field_10;
    if (v9 >= result) JUMPOUT(0x1400e9847);
    result = ptr3->field_8;
    *(result + v9) = a2;
    result = ptr3->field_0;
    a2 = ptr3->field_10;
    result -= a2;
    if (result <= 2) JUMPOUT(0x1400e95ab);
    result = ptr3->field_8;
    *(result + a2 + 2) = 12;
    *(result + a2) = 0x488;
    a2 += 3;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 2) JUMPOUT(0x1400e95d1);
    result = ptr3->field_8;
    *(result + a2 + 2) = 193;
    *(result + a2) = 0xFF48;
    result = a2 + 3;
    ptr3->field_10 = result;
    a2 += 8;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    ptr -= a2;
    if (ptr3->field_0 == result) JUMPOUT(0x1400e95f7);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    ++result;
    ptr3->field_10 = result;
    a1 = (size_t *)ptr;
    if (ptr != ptr) JUMPOUT(0x1400e9859);
    a1 = ptr3->field_0;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 3) JUMPOUT(0x1400e9620);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result) = ptr;
    result += 4;
    ptr3->field_10 = result;
    a2 = (int)ptr2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e9882);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(__int64 *)((__int64)result + (__int64)ptr2 + 6) = a1;
    ptr2 = ptr3->field_10;
    if (v_30 == 5) {
        a1 = rsp + 48;
        sub_1400FAE80(a1);
    }
    ptr = (struct Struct_1_t *)v_38;
    ptr->field_28 = ptr2;
    a1 = ptr3->field_0;
    result = ptr3->field_10;
    a1 = (size_t *)((__int64)a1 - (__int64)result);
    if (a1 <= 4) JUMPOUT(0x1400e9649);
    a1 = ptr3->field_8;
    *(__int64 *)((__int64)a1 + (__int64)result + 4) = 0;
    *(__int64 *)((__int64)a1 + (__int64)result) = 233;
    result += 5;
    ptr3->field_10 = result;
    a2 = v2;
    a2 += 10;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    a1 = (size_t *)result;
    a1 -= a2;
    v5 = (__int64)a1;
    if (a1 != a1) JUMPOUT(0x1400e98ab);
    if (result < a2) {
        return v5;
    }
    result = ptr3->field_8;
    *(result + v2 + 6) = a1;
    a1 = ptr->field_0;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v5 = ptr3->field_10;
    v7 = v5;
    v7 -= a2;
    result = (__int64 *)v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    dst = ptr3->field_8;
    result = (__int64 *)v_30;
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    a1 = ptr->field_8;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v7 = v5;
    v7 -= a2;
    v8 = v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    a1 = ptr->field_10;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v7 = v5;
    v7 -= a2;
    v8 = v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    a1 = ptr->field_18;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v7 = v5;
    v7 -= a2;
    v8 = v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    a1 = ptr->field_20;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v7 = v5;
    v7 -= a2;
    v8 = v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    a1 = ptr->field_28;
    a2 = (int)a1;
    a2 += 5;
    if ((a2 < 0)) JUMPOUT(0x1400e970a);
    v7 = v5;
    v7 -= a2;
    v8 = v7;
    if (v7 != v7) JUMPOUT(0x1400e9733);
    ++a1;
    if (a1 > -5) {
        return (__int64)a1;
    }
    if (v5 < a2) {
        return (__int64)a1;
    }
    *(__int64 *)((__int64)dst + (__int64)a1) = v7;
    if (result != 0) {
        off_140108030(a1, a2, v5, dst);
        off_140108038(result, 0, ptr);
    }
    result = ptr3->field_0;
    a2 = ptr3->field_10;
    result -= a2;
    if (result <= 4) JUMPOUT(0x1400e9672);
    result = ptr3->field_8;
    *(result + a2 + 4) = 36;
    *(result + a2) = 0x46F0FF3;
    a2 += 5;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e9698);
    result = ptr3->field_8;
    *(result + a2) = 0x30C48348;
    a2 += 4;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 5) JUMPOUT(0x1400e96be);
    result = ptr3->field_8;
    *(result + a2 + 4) = 0x1484;
    *(result + a2) = 0x7F0F42F3;
    a2 += 6;
    ptr3->field_10 = a2;
    result = ptr3->field_0;
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e96e4);
    result = ptr3->field_8;
    *(result + a2) = v4;
    a2 += 4;
    ptr3->field_10 = a2;
    return (__int64)result;
}