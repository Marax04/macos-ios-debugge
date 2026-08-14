// inferred from 2 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int64 field_2; // offset 2
    char _pad_2[30];
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[1];
    char field_1; // offset 1
    __int64 field_2; // offset 2
    char _pad_2[30];
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `i`
struct Struct_4_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 3 accesses on `ptr3`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400831E0();
__int64 sub_1400850E1();
__int64 sub_14008535E();
extern __int64 off_140123AE8;
extern __int64 off_140123AD8;
extern __int64 off_14011EFF8;
extern __int64 off_14011F010;
extern __int64 off_140123B88;

__int64 __fastcall sub_140084BD0(int *a1, size_t *a2,struct Struct_1_t *a3) {
    __int64 rsp;
    int v_20;
    int v_40;
    int v_41;
    int v_42;
    int v_43;
    int v_44;
    int v_4c;
    int v_50;
    int v_78;
    int v_80;
    struct Struct_2_t *ptr;
    __int64 *result;
    __int64 v6;
    __int64 v2;
    struct Struct_3_t *ptr2;
    struct Struct_5_t *ptr3;
    struct Struct_4_t *i;
    __int64 v8;
    __int64 i2;
    __int64 v10;

    ptr = (struct Struct_2_t *)a2;
    result = ptr - 200;
    if (result <= 39) {
        v6 = &off_140123AE8;
        switch ((__int64)result) {
            case 1:
                *a1 = 46;
                a1[5] = 4;
                a1[7] = 4;
                a1[9] = 4;
                a1[11] = 4;
                a1[13] = 0;
                break;
            case 36:
                *a1 = 116;
                a1[5] = 0;
                return v6;
            case 37:
                result = i->field_3;
                result = (__int64 *)((__int64)(__int64)result >> 4);
                a2 = i->field_0;
                a3 = (struct Struct_1_t *)a2;
                a3 = (struct Struct_1_t *)((__int64)(__int64)a3 >> 1);
                if (i->field_2 != 0) a3 = result;
                a2 = (size_t *)((__int64)(__int64)a2 & 32);
                result = 0;
                ++result;
                a2 = 3;
                if (((__int64)a3 & 1) == 0) a2 = result;
                *a1 = 116;
                a1[5] = 0;
                a1[5] = a2;
                a1[5] = 0;
                a1[7] = 256;
                a1[7] = 2;
                return (__int64)a2;
            case 38:
                *a1 = 117;
                a1[5] = 256;
                a1[5] = 2;
                a1[7] = 0;
                a1[7] = 0;
                return (__int64)a2;
            case 39:
                result = i->field_3;
                a2 = i->field_0;
                result = (__int64 *)((__int64)(__int64)result >> 4);
                a3 = (struct Struct_1_t *)a2;
                a3 = (struct Struct_1_t *)((__int64)(__int64)a3 >> 1);
                if (i->field_2 != 0) a3 = result;
                a2 = (size_t *)((__int64)(__int64)a2 & 32);
                result = 0;
                ++result;
                a2 = 3;
                if (((__int64)a3 & 1) == 0) a2 = result;
                *a1 = 117;
                a1[5] = 256;
                a1[5] = 2;
                a1[7] = 0;
                a1[7] = a2;
                a1[7] = 0;
                a1[9] = 4;
                a1[11] = 4;
                a1[13] = 2;
                break;
            default:
                result = ptr - 108;
                if (result <= 3) {
                    a2 = &off_140123AD8;
                    switch ((__int64)result) {
                        case 0:
                            *a1 = 118;
                            return (__int64)a2;
                        case 1:
                            result = i->field_3;
                            result = (__int64 *)((__int64)(__int64)result >> 4);
                            a2 = i->field_0;
                            a3 = (struct Struct_1_t *)a2;
                            a3 = (struct Struct_1_t *)((__int64)(__int64)a3 >> 1);
                            if (i->field_2 != 0) a3 = result;
                            result = 0;
                            result = (((__int64)a2 & 32) == 0) ? 1 : 0;
                            a2 = 2;
                            if (((__int64)a3 & 1) == 0) a2 = result;
                            result = &off_14011EFF8;
                            result = result[(__int64)a2];
                            *a1 = 118;
                            return (__int64)result;
                        case 2:
                            *a1 = 119;
                            a1[5] = 2;
                            a1[6] = 1;
                            return (__int64)result;
                        case 3:
                            result = i->field_3;
                            result = (__int64 *)((__int64)(__int64)result >> 4);
                            a2 = i->field_0;
                            a3 = (struct Struct_1_t *)a2;
                            a3 = (struct Struct_1_t *)((__int64)(__int64)a3 >> 1);
                            if (i->field_2 != 0) a3 = result;
                            result = 0;
                            result = (((__int64)a2 & 32) == 0) ? 1 : 0;
                            a2 = 2;
                            if (((__int64)a3 & 1) == 0) a2 = result;
                            result = &off_14011F010;
                            result = result[(__int64)a2];
                            *a1 = 119;
                            a1[5] = 2;
                            a1[6] = result;
                            a1[7] = 4;
                            a1[9] = 4;
                            a1[11] = 4;
                            a1[13] = 1;
                            break;
                        default:
                            v2 = ptr - 192;
                            if (v2 <= 19) {
                                result = &off_140123B88;
                                switch (v2) {
                                    case 0:
                                        ptr2 = (struct Struct_3_t *)a1;
                                        result = 0;
                                        return (__int64)result;
                                    case 1:
                                        ptr2 = (struct Struct_3_t *)a1;
                                        result = i->field_3;
                                        result = (__int64 *)((__int64)(__int64)result >> 4);
                                        a1 = i->field_0;
                                        a2 = (size_t *)a1;
                                        a2 = (size_t *)((__int64)(__int64)a2 >> 1);
                                        if (i->field_2 != 0) a2 = result;
                                        a1 = (int *)((__int64)(__int64)a1 & 32);
                                        result = 0;
                                        ++result;
                                        a1 = (int *)result;
                                        result = 3;
                                        if (((__int64)a2 & 1) == 0) result = a1;
                                        v_20 = 0;
                                        a1 = rsp + 64;
                                        ptr3 = (struct Struct_5_t *)a3;
                                        sub_1400831E0(a1, a3, i, result);
                                        i = (struct Struct_4_t *)v_40;
                                        a2 = (size_t *)v_41;
                                        a3 = (struct Struct_1_t *)v_42;
                                        result = (__int64 *)v_43;
                                        if (i != 4) {
                                            a1 = (int *)v_4c;
                                            v_80 = (int)a1;
                                            a1 = (int *)v_44;
                                            v_78 = (int)a1;
                                            a1 = (int *)v_50;
                                            a1 = (int *)((__int64)(__int64)a1 << 3);
                                            v8 = 0x171516151B1A1918;
                                            v8 >>= (__int64)a1;
                                            if (v2 < 2) {
                                                i2 = ptr3->field_10;
                                                if (i2 >= ptr3->field_8) JUMPOUT(0x1400850ce);
                                                a1 = ptr3->field_0;
                                                a1 = *(a1 + i2);
                                                ++i2;
                                                ptr3->field_10 = i2;
                                            } else {
                                                ptr += 0xFFFFFF30;
                                                if (ptr >= 2) JUMPOUT(0x1400850de);
                                                a1 = 1;
                                            }
                                            i2 = 2;
                                            return sub_1400850E1();
                                        } else {
                                            *(__int64 *)ptr2 = (__int64)(a2);
                                            ptr2->field_1 = a3;
                                            ptr2->field_2 = result;
                                            ptr2->field_28 = 5;
                                            return i2;
                                        }
                                        break;
                                    case 2:
                                        break;
                                    case 6:
                                        ptr = (struct Struct_2_t *)a1;
                                        v_20 = 0;
                                        a1 = rsp + 64;
                                        ptr2 = (struct Struct_3_t *)a3;
                                        sub_1400831E0(a1, a3, i, 0);
                                        a3 = (struct Struct_1_t *)v_40;
                                        a1 = (int *)v_41;
                                        a2 = (size_t *)v_42;
                                        result = (__int64 *)v_43;
                                        if (a3 != 4) JUMPOUT(0x140085124);
                                        *(__int64 *)ptr = (__int64)(a1);
                                        ptr->field_1 = a2;
                                        ptr->field_2 = result;
                                        ptr->field_28 = 5;
                                        return (__int64)result;
                                    case 7:
                                        ptr = (struct Struct_2_t *)a1;
                                        result = i->field_3;
                                        result = (__int64 *)((__int64)(__int64)result >> 4);
                                        v2 = i->field_0;
                                        a1 = (int *)v2;
                                        a1 = (int *)((__int64)(__int64)a1 >> 1);
                                        ptr2 = (struct Struct_3_t *)a1;
                                        if (i->field_2 != 0) ptr2 = result;
                                        result = (__int64 *)v2;
                                        result = (__int64 *)((__int64)(__int64)result & 32);
                                        a1 = 0;
                                        ++a1;
                                        result = 3;
                                        if (((__int64)ptr2 & 1) == 0) result = a1;
                                        v_20 = 0;
                                        a1 = rsp + 64;
                                        ptr3 = (struct Struct_5_t *)a3;
                                        sub_1400831E0(a1, a3, i, result);
                                        result = (__int64 *)v_40;
                                        if (result != 4) JUMPOUT(0x140085196);
                                        result = (__int64 *)v_41;
                                        a1 = (int *)v_43;
                                        *(__int64 *)ptr = (__int64)(result);
                                        ptr->field_2 = a1;
                                        ptr->field_28 = 5;
                                        return (__int64)a1;
                                }
                            }
                            result = (__int64 *)a2;
                            result = (__int64 *)((__int64)(__int64)result & 248);
                            if (result == 176) JUMPOUT(0x1400851ff);
                            if (result != 184) JUMPOUT(0x140085248);
                            v6 = i->field_3;
                            v6 >>= 4;
                            i2 = i->field_0;
                            result = (__int64 *)i2;
                            result = (__int64 *)((__int64)(__int64)result >> 1);
                            ptr = (struct Struct_2_t *)result;
                            if (i->field_2 != 0) result = v6;
                            i2 &= 32;
                            i = 0;
                            ++i;
                            v6 = (__int64)i;
                            i = 3;
                            if (((__int64)ptr & 1) == 0) i = v6;
                            if (i == 3) JUMPOUT(0x14008530d);
                            v6 = (__int64)i;
                            if (i != 2) JUMPOUT(0x140085336);
                            v10 = ((__int64 *)a3)[2];
                            if (v10 > -5) JUMPOUT(0x14008580a);
                            i2 = v10 + 4;
                            if (i2 > a3->field_8) JUMPOUT(0x14008580a);
                            ptr = a3->field_0;
                            ((__int64 *)a3)[2] = (__int64)(i2);
                            a3 = *(__int64 *)(ptr + v10);
                            return sub_14008535E();
                    }
                    return (__int64)a3;
                }
                return (__int64)a3;
        }
        return (__int64)a3;
    }
    return (__int64)result;
}