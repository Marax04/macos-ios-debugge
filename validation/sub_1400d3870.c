// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_3_t {
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
__int64 sub_1400F3B80();
__int64 sub_1400D5078();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011B3E0;
extern __int64 off_14011B3C3;
extern __int64 off_14011D3F8;
extern __int64 off_14011BC78;
extern __int64 off_14011BC68;
extern __int64 off_14011BC98;
extern __int64 off_14011BC90;

__int64 __fastcall sub_1400D3870(struct Struct_1_t *a1, int *a2, size_t a3, int a4) {
    __int64 rsp;
    __int64 v_20;
    int v_40;
    int v_68;
    int v_70;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    __int64 *result;
    __int64 v2;
    __int64 v4;
    int v8;
    __int64 v5;
    __int64 *dst;

    v_70 = a4;
    v_68 = a3;
    v_40 = (int)a2;
    ptr = (struct Struct_2_t *)a1;
    sub_14002EDF0(0, 8);
    if (result != 0) {
        ptr2 = (struct Struct_3_t *)result;
        *result = 0x24648B4C;
        result = ptr->field_0;
        a2 = ptr->field_10;
        ptr2->field_4 = 56;
        result = (__int64 *)((__int64)result - (__int64)a2);
        if (result <= 4) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr, a2, 5, 1);
                a2 = ptr->field_10;
            } while (true);
        }
        result = ptr->field_8;
        a1 = ptr2->field_4;
        *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
        a1 = ptr2->field_0;
        *(__int64 *)((__int64)result + (__int64)a2) = a1;
        a2 += 5;
        ptr->field_10 = a2;
        off_140108030(a1, a2);
        off_140108038(result, 0, ptr2);
        a1 = (struct Struct_1_t *)v_40;
        v2 = a1->field_0;
        result = v2 + 1;
        *(__int64 *)a1 = (__int64)(result);
        sub_14002EDF0(0, 8);
        if (result != 0) {
            ptr2 = (struct Struct_3_t *)result;
            *result = 0x246C8B4C;
            result = ptr->field_0;
            a2 = ptr->field_10;
            ptr2->field_4 = 64;
            result = (__int64 *)((__int64)result - (__int64)a2);
            if (result <= 4) {
                v_20 = 1;
                sub_1400F2D20(ptr, a2, 5, 1);
                a2 = ptr->field_10;
            }
            result = ptr->field_8;
            a1 = ptr2->field_4;
            *(__int64 *)((__int64)result + (__int64)a2 + 4) = a1;
            a1 = ptr2->field_0;
            *(__int64 *)((__int64)result + (__int64)a2) = a1;
            a2 += 5;
            ptr->field_10 = a2;
            off_140108030(a1, a2);
            off_140108038(result, 0, ptr2);
            result = v2 + 2;
            a1 = (struct Struct_1_t *)v_40;
            *(__int64 *)a1 = (__int64)(result);
            sub_14002EDF0(0, 11);
            if (result != 0) {
                ptr2 = (struct Struct_3_t *)result;
                *result = 0x84C7;
                *(result + 2) = 36;
                result = 0x6170786500000088;
                ptr2->field_3 = result;
                result = ptr->field_0;
                a2 = ptr->field_10;
                result = (__int64 *)((__int64)result - (__int64)a2);
                if (result <= 10) {
                    v_20 = 1;
                    sub_1400F2D20(ptr, a2, 11, 1);
                    a2 = ptr->field_10;
                }
                result = ptr->field_8;
                a1 = ptr2->field_7;
                *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                a1 = ptr2->field_0;
                *(__int64 *)((__int64)result + (__int64)a2) = a1;
                a2 += 11;
                ptr->field_10 = a2;
                off_140108030(a1, a2);
                off_140108038(result, 0, ptr2);
                sub_14002EDF0(0, 11);
                if (result != 0) {
                    ptr2 = (struct Struct_3_t *)result;
                    *result = 0x84C7;
                    *(result + 2) = 36;
                    result = 0x3320646E0000008C;
                    ptr2->field_3 = result;
                    result = ptr->field_0;
                    a2 = ptr->field_10;
                    result = (__int64 *)((__int64)result - (__int64)a2);
                    if (result <= 10) {
                        v_20 = 1;
                        sub_1400F2D20(ptr, a2, 11, 1);
                        a2 = ptr->field_10;
                    }
                    result = ptr->field_8;
                    a1 = ptr2->field_7;
                    *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                    a1 = ptr2->field_0;
                    *(__int64 *)((__int64)result + (__int64)a2) = a1;
                    a2 += 11;
                    ptr->field_10 = a2;
                    off_140108030(a1, a2);
                    off_140108038(result, 0, ptr2);
                    result = v2 + 4;
                    a1 = (struct Struct_1_t *)v_40;
                    *(__int64 *)a1 = (__int64)(result);
                    sub_14002EDF0(0, 11);
                    if (result != 0) {
                        ptr2 = (struct Struct_3_t *)result;
                        *result = 0x84C7;
                        *(result + 2) = 36;
                        result = 0x79622D3200000090;
                        ptr2->field_3 = result;
                        result = ptr->field_0;
                        a2 = ptr->field_10;
                        result = (__int64 *)((__int64)result - (__int64)a2);
                        if (result <= 10) {
                            v_20 = 1;
                            sub_1400F2D20(ptr, a2, 11, 1);
                            a2 = ptr->field_10;
                        }
                        result = ptr->field_8;
                        a1 = ptr2->field_7;
                        *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                        a1 = ptr2->field_0;
                        *(__int64 *)((__int64)result + (__int64)a2) = a1;
                        a2 += 11;
                        ptr->field_10 = a2;
                        off_140108030(a1, a2);
                        off_140108038(result, 0, ptr2);
                        sub_14002EDF0(0, 11);
                        if (result != 0) {
                            ptr2 = (struct Struct_3_t *)result;
                            *result = 0x84C7;
                            *(result + 2) = 36;
                            result = 0x6B20657400000094;
                            ptr2->field_3 = result;
                            result = ptr->field_0;
                            a2 = ptr->field_10;
                            result = (__int64 *)((__int64)result - (__int64)a2);
                            if (result <= 10) {
                                v_20 = 1;
                                sub_1400F2D20(ptr, a2, 11, 1);
                                a2 = ptr->field_10;
                            }
                            result = ptr->field_8;
                            a1 = ptr2->field_7;
                            *(__int64 *)((__int64)result + (__int64)a2 + 7) = a1;
                            a1 = ptr2->field_0;
                            *(__int64 *)((__int64)result + (__int64)a2) = a1;
                            a2 += 11;
                            ptr->field_10 = a2;
                            off_140108030(a1, a2);
                            v4 = 0;
                            off_140108038(result, 0, ptr2);
                            a1 = (struct Struct_1_t *)v_68;
                            result = a1 + 32;
                            v8 = 0xCBF29CE4;
                            do {
                                a2 = (a1 == 0) ? 1 : 0;
                                a3 = (a1 == result) ? 1 : 0;
                                a3 |= (__int64)a2;
                                a2 = a1 + 1;
                                a1 = a1->field_0;
                                v8 ^= (__int64)a1;
                                v8 *= 0x1000193;
                                a1 = (struct Struct_1_t *)a2;
                            } while (true);
                        }
                    }
                }
            }
            sub_1400F3326(1, 11);
            sub_1400F3326(1, 6);
            sub_1400F3326(1, 7);
            result = &off_14011B3E0;
            v_20 = (__int64)result;
            a1 = &off_14011B3C3;
            a4 = &off_14011D3F8;
            a3 = rsp + 40;
            sub_1400F3B80(a1, 23, a3, a4);
            result = &off_14011BC78;
            v_20 = (__int64)result;
            a1 = &off_14011BC68;
            a4 = &off_14011D3F8;
            a3 = rsp + 40;
            sub_1400F3B80(a1, 10, a3, a4);
            sub_1400F3326(1, 5);
            result = &off_14011BC98;
            v_20 = (__int64)result;
            a1 = &off_14011BC90;
            a4 = &off_14011D3F8;
            a3 = rsp + 40;
            sub_1400F3B80(a1, 8, a3, a4);
            result = (a4 == 0) ? 1 : 0;
            v5 = (a3 != 5) ? 1 : 0;
            if ((v5 & (__int64)result) != 0) JUMPOUT(0x1400d4fe1);
            result = (__int64 *)a4;
            a2 = (int *)((__int64)(__int64)a2 << 3);
            a2 = (int *)((__int64)(__int64)a2 | a3);
            if (a4 == a4) JUMPOUT(0x1400d5021);
            a2 = (int *)((__int64)(__int64)a2 | 128);
            v5 = a1->field_0;
            v4 = ((__int64 *)a1)[2];
            if (v4 == v5) JUMPOUT(0x1400d509d);
            result = v4 + 1;
            dst = a1->field_8;
            *(dst + v4) = a2;
            ((__int64 *)a1)[2] = (__int64)(result);
            if (a3 == 4) {
                if (result == v5) JUMPOUT(0x1400d5111);
                *(dst + v4 + 1) = 36;
                v4 += 2;
                ((__int64 *)a1)[2] = (__int64)(v4);
                result = (__int64 *)v4;
            }
            v5 -= (__int64)result;
            if (v5 <= 3) JUMPOUT(0x1400d514b);
            *(__int64 *)((__int64)dst + (__int64)result) = a4;
            result += 4;
            ((__int64 *)a1)[2] = (__int64)(result);
            return sub_1400D5078();
        }
    }
    sub_1400F3326(1, 8);
    return (__int64)result;
}