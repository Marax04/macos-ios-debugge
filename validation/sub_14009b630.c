// inferred from 4 accesses on `result`
struct Struct_1_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

// inferred from 4 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[2];
    __int16 field_2; // offset 2
    int field_4; // offset 4
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[48];
    __int64 field_48; // offset 72
};

__int64 sub_1400FAE80();
__int64 sub_14002EDF0();
__int64 sub_1400F5F90();
__int64 sub_1400972B0();
__int64 sub_1400F3360();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14009B630(int *a1, __int64 *a2, size_t a3, int a4) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    int v_5c;
    int v_60;
    int v_68;
    int v_70;
    __int64 v3;
    struct Struct_1_t *result;
    __int64 v6;
    struct Struct_2_t *ptr;
    __int64 v5;
    __int64 *dst;
    struct Struct_4_t *ptr3;
    __int64 i;
    __int64 v11;
    __int64 v10;
    struct Struct_3_t *ptr2;

    if (a2[28] >= 10) {
        v3 = a2[19];
        result = a2[19];
        result = (struct Struct_1_t *)((__int64)(__int64)result | v3);
        if ((result == 0)) {
            *(a1 + 4) = 0;
        } else {
            result = a2[4];
            v6 = a2[5];
            ptr = result - 28;
            v5 = v6 + v6*8;
            v5 += v5*2;
            dst = v5 + v6;
            while (dst != 0) {
                ptr3 = ptr->field_24;
                i = ptr->field_28;
                v11 = ptr->field_2C;
                if (v11 > ptr3) ptr3 = v11;
                ptr3 += i;
                if (!((ptr3 < 0))) {
                    ptr += 28;
                    dst -= 28;
                    v10 = v3;
                    v10 -= i;
                    if (v10 < v11) {
                        ptr = ptr->field_14;
                        v3 = v10;
                        v3 += (__int64)ptr;
                        dst = a2[2];
                        if (v3 < dst) {
                            ptr = v3 + 40;
                            if (dst < ptr) {
                                *a1 = 1;
                            } else {
                                ptr2 = *(a2 + 8);
                                v10 = *(__int64 *)(ptr2 + v3 + 24);
                                v_60 = 0;
                                v_68 = 8;
                                v_70 = 0;
                                ptr = a2[9];
                                ptr3 = (struct Struct_4_t *)a2;
                                v_50 = a4;
                                if (v10 != 0) {
                                    a4 = 0;
                                    v10 -= (__int64)ptr;
                                    if (v10 >= 0) a4 = v10;
                                    v10 = 0xFFFFFFFF;
                                    if (a4 >= v10) a4 = v10;
                                    result -= 28;
                                    v5 += v6;
                                    while (v5 != 0) {
                                        v11 = result->field_24;
                                        i = result->field_28;
                                        v6 = result->field_2C;
                                        if (v6 > v11) v11 = v6;
                                        v11 += i;
                                        if (!((v11 < 0))) {
                                            result += 28;
                                            v5 -= 28;
                                            v10 = a4;
                                            v10 -= i;
                                            if (v10 < v6) {
                                                result = result->field_14;
                                                v11 = v10;
                                                v11 += (__int64)result;
                                                if (v11 >= dst) {
                                                    ptr2 = (struct Struct_3_t *)a1;
                                                    result = (struct Struct_1_t *)a3;
                                                    ptr = (struct Struct_2_t *)((__int64)ptr + (__int64)result);
                                                    dst = 16;
                                                    v11 = 0;
                                                    i = 0;
                                                } else {
                                                    ptr2 += v11;
                                                    v11 += 8;
                                                    result = 8;
                                                    i = 0;
                                                    a4 = rsp + 96;
                                                    while (dst >= v11) {
                                                        v10 = ((__int64 *)ptr2)[i];
                                                        if (v10 != 0) {
                                                            if (i == v_60) {
                                                                ptr = (struct Struct_2_t *)a1;
                                                                v_5c = a3;
                                                                sub_1400FAE80(a4, a2, a3, a4);
                                                                a4 = rsp + 96;
                                                                a3 = v_5c;
                                                                a2 = (__int64 *)ptr3;
                                                                a1 = (int *)ptr;
                                                                result = (struct Struct_1_t *)v_68;
                                                            }
                                                            ((__int64 *)result)[i] = (__int64)(v10);
                                                            ++i;
                                                            v_70 = i;
                                                            v11 += 8;
                                                            ptr2 = (struct Struct_3_t *)a1;
                                                            ptr = (struct Struct_2_t *)a3;
                                                            ptr += a2[9];
                                                            i = 64;
                                                            v11 = 512;
                                                            dst = 528;
                                                            sub_14002EDF0(0, dst, a3, a4);
                                                            if (result == 0) JUMPOUT(0x14009ba14);
                                                            v_38 = (__int64)dst;
                                                            v_40 = (__int64)result;
                                                            *(__int64 *)result = (__int64)(ptr);
                                                            v_48 = 8;
                                                            ptr = (struct Struct_2_t *)v_68;
                                                            a1 = (int *)ptr3;
                                                            a2 = (__int64 *)v_50;
                                                            a4 = 8;
                                                            if (i != 0) {
                                                                dst = 0;
                                                                v5 = rsp + 56;
                                                                do {
                                                                    v10 = *(__int64 *)((__int64)ptr + (__int64)dst);
                                                                    a3 = v_38;
                                                                    a3 -= a4;
                                                                    sub_1400F5F90(v5, a4, 8, a4);
                                                                    v5 = rsp + 56;
                                                                    a2 = (__int64 *)v_50;
                                                                    result = (struct Struct_1_t *)v_40;
                                                                    a4 = v_48;
                                                                    *(__int64 *)(result + a4) = (__int64)(v10);
                                                                    a4 += 8;
                                                                    v_48 = a4;
                                                                    dst += 8;
                                                                } while (v11 != dst);
                                                                dst = (__int64 *)v_38;
                                                            }
                                                            dst -= a4;
                                                            if (dst <= 7) JUMPOUT(0x14009b9dc);
                                                            dst = (__int64 *)v_40;
                                                            *(dst + a4) = 0;
                                                            a4 += 8;
                                                            v_20 = a4;
                                                            v_28 = 0x40000040;
                                                            sub_1400972B0(ptr3, a2, 8, dst);
                                                            a1 = (int *)result;
                                                            a1 = (int *)((__int64)(__int64)a1 >> 32);
                                                            if (((__int64)result & 1) == 0) {
                                                                a2 = v3 + 32;
                                                                a3 = ptr3->field_10;
                                                                if (a2 > a3) JUMPOUT(0x14009ba01);
                                                                result = (struct Struct_1_t *)a1;
                                                                result += ptr3->field_48;
                                                                a2 = ptr3->field_8;
                                                                *(a2 + v3 + 24) = result;
                                                                ++i;
                                                                ptr2->field_8 = a1;
                                                                ptr2->field_10 = i;
                                                                *(__int64 *)ptr2 = (__int64)(0);
                                                            } else {
                                                                result = (struct Struct_1_t *)((__int64)(__int64)result >> 16);
                                                                ptr2->field_2 = result;
                                                                ptr2->field_4 = a1;
                                                                *(__int64 *)ptr2 = (__int64)(1);
                                                            }
                                                            if (v_38 != 0) {
                                                                off_140108030(a1, a2, a3);
                                                                off_140108038(result, 0, dst);
                                                            }
                                                            if (v_60 != 0) {
                                                                off_140108030();
                                                                off_140108038(result, 0, ptr);
                                                            }
                                                            return (__int64)result;
                                                        }
                                                    }
                                                    v11 =  + i*8;
                                                    dst = (__int64 *)v11;
                                                    dst += 16;
                                                    if ((dst >= 0)) JUMPOUT(0x14009ba21);
                                                    sub_1400F3360();
                                                    return (__int64)dst;
                                                }
                                                return (__int64)dst;
                                            }
                                        }
                                    }
                                }
                                return (__int64)dst;
                            }
                            return (__int64)dst;
                        }
                    }
                }
            }
        }
        return (__int64)dst;
    }
    return (__int64)result;
}