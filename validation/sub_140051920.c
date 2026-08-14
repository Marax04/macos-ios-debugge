// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[4];
    __int64 field_C; // offset 12
};

__int64 sub_140011760();
__int64 sub_1400F5F90();
extern __int64 off_140051B80;
extern __int64 off_1401175D8;
extern __int64 off_140115058;
extern __int64 off_140051DC0;
extern __int64 off_140051AE0;

__int64 __fastcall sub_140051920(int *a1, __int64 *a2) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_28;
    __int64 v_30;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    char *str;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *result;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    if (a1[2] != 1) {
        if (ptr2->field_0 != 0) {
            result = ptr2 + 4;
            v_20 = (__int64)result;
            result = rsp + 32;
            v_28 = (__int64)result;
            result = &off_140051B80;
            v_30 = (__int64)result;
            result = &off_1401175D8;
            str = (char *)result;
            v_40 = 1;
            v_58 = 0;
            result = rsp + 40;
            v_48 = (__int64)result;
            v_50 = 1;
            a2 = &off_140115058;
            sub_140011760(ptr, a2, str);
            a1 = (int *)result;
            result = 1;
            if (a1 == 0) {
                if (ptr2->field_C != 2) {
                    ptr2 += 12;
                    v_20 = (__int64)ptr2;
                    result = rsp + 32;
                    v_28 = (__int64)result;
                    result = &off_140051DC0;
                    v_30 = (__int64)result;
                    result = &off_1401175D8;
                    str = (char *)result;
                    v_40 = 1;
                    v_58 = 0;
                    result = rsp + 40;
                    v_48 = (__int64)result;
                    v_50 = 1;
                    a2 = &off_140115058;
                    sub_140011760(ptr, a2, str);
                    return (__int64)a2;
                } else {
                    result = 0;
                }
            }
            return (__int64)result;
        }
    } else {
        result = ptr2 + 18;
        v_20 = (__int64)result;
        result = rsp + 32;
        v_28 = (__int64)result;
        result = &off_140051AE0;
        v_30 = (__int64)result;
        result = &off_1401175D8;
        str = (char *)result;
        v_40 = 1;
        v_58 = 0;
        result = rsp + 40;
        v_48 = (__int64)result;
        v_50 = 1;
        a2 = &off_140115058;
        sub_140011760(ptr, a2, str);
        a1 = (int *)result;
        result = 1;
        if (a1 == 0) {
            if (ptr2->field_0 != 0) {
                result = ptr2 + 4;
                v_20 = (__int64)result;
                a2 = ptr->field_10;
                if (ptr->field_0 == a2) {
                    sub_1400F5F90(ptr, a2, 1);
                    a2 = ptr->field_10;
                }
                result = ptr->field_8;
                *(__int64 *)((__int64)result + (__int64)a2) = 84;
                ++a2;
                ptr->field_10 = a2;
                return (__int64)a2;
            }
            return (__int64)a2;
        }
        return (__int64)a2;
    }
    return (__int64)result;
}