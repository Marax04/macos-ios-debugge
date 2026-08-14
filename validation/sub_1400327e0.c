// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char field_0; // offset 0
    char field_1; // offset 1
    __int64 field_2; // offset 2
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F6840();
__int64 sub_1400F27F0();

__int64 __fastcall sub_1400327E0(size_t *a1,struct Struct_1_t *a2, int *a3) {
    int v_20;
    __int64 v4;
    struct Struct_2_t *ptr;
    __int64 v2;
    __int64 result;
    __int64 v7;
    int v5;
    __int64 v8;
    __int64 v6;

    v4 = (__int64)a3;
    ptr = (struct Struct_2_t *)a1;
    v2 = a1[2];
    result = 1;
    v7 = 0;
    if (v2 >= 3) {
        a3 = ptr->field_8;
        a1 = *(a3 + v2 - 2);
        v5 = (int)a1;
        v5 &= 240;
        if (v5 == 160) {
            if (*(a3 + v2 - 3) == 237) {
                v7 = *(a3 + v2 - 1);
                a1 = (size_t *)((__int64)(__int64)a1 & 15);
                v7 &= 63;
                a1 = (size_t *)((__int64)(__int64)a1 << 16);
                v7 <<= 10;
                v7 |= (__int64)a1;
                result = 0;
            }
        }
    }
    if (v4 >= 3) {
        if (a2->field_0 == 237) {
            v8 = a2->field_1;
            a1 = (size_t *)v8;
            a1 = (size_t *)((__int64)(__int64)a1 & 240);
            if (a1 == 176) {
                if (result == 0) {
                    result = a2->field_2;
                    result &= 63;
                    v8 &= 15;
                    v8 <<= 6;
                    if (v2 >= 3) {
                        v2 -= 3;
                        ptr->field_10 = v2;
                    }
                    v8 |= result;
                    a3 = v4 + 1;
                    result = ptr->field_0;
                    a1 = (size_t *)result;
                    a1 -= v2;
                    if (a3 > a1) JUMPOUT(0x140032a52);
                    v8 |= v7;
                    v7 = v8 + 0x10000;
                    v6 = v7;
                    v6 >>= 18;
                    if (a1 <= 3) JUMPOUT(0x140032a84);
                    a2 += 3;
                    a1 = ptr->field_8;
                    a3 = (int *)v8;
                    a3 = (int *)((__int64)(__int64)a3 & 63);
                    a3 = (int *)((__int64)(__int64)a3 << 24);
                    v8 <<= 10;
                    v8 &= 0x3F0000;
                    v8 |= (__int64)a3;
                    v7 >>= 4;
                    v7 &= 0x3F00;
                    v7 |= v8;
                    a3 = v6 + v7;
                    a3 += 0x808080F0;
                    *(a1 + v2) = a3;
                    v2 += 4;
                    ptr->field_10 = v2;
                    v4 -= 3;
                    result -= v2;
                    if (v4 > result) {
                        v_20 = 1;
                        v7 = (__int64)a2;
                        sub_1400F6840(ptr, v2, v4, 1);
                        a1 = ptr->field_8;
                        v2 = ptr->field_10;
                    }
                } else {
                    if (ptr->field_18 != 0) {
                        if (v4 != 0) {
                            result = a2 + v4;
                            a1 = a2 + 1;
                            a3 = (int *)a2;
                            do {
                                v5 = *a3;
                                a3 = (int *)a1;
                                a1 = 0;
                                a1 = (a3 != result) ? 1 : 0;
                                a1 = (size_t *)((__int64)a1 + (__int64)a3);
                            } while (a3 != result);
                        }
                    }
                    result = ptr->field_0;
                    result -= v2;
                    if (v4 > result) JUMPOUT(0x140032a29);
                    a1 = ptr->field_8;
                }
                a1 += v2;
                sub_1400F27F0(a1, v7, v4);
                v2 += v4;
                ptr->field_10 = v2;
                return v2;
            }
        }
    }
    return result;
}