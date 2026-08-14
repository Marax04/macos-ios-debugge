// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
    char _pad_12[6];
    __int64 field_20; // offset 32
};

__int64 sub_140013110();
__int64 sub_140023DFC();
__int64 sub_140023E98();
__int64 sub_140024D41();
__int64 sub_140018400();
extern __int64 off_1401109D2;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;
extern __int64 off_140117680;

__int64 __fastcall sub_140023BC4(int *a1, int a2) {
    int v_8;
    char *src;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v5;
    __int64 v2;
    __int64 *src2;
    __int64 v10;
    __int64 v8;
    __int64 result;
    __int64 v11;
    __int64 v9;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 == 0) {
        v7 = ptr->field_20;
        if (v7 != 0) {
            a2 = &off_1401109D2;
            v5 = 1;
            return sub_140013110();
        }
    } else {
        v2 = a2;
        src2 = src - 8;
        sub_140023DFC(src2, ptr);
        v10 = *src2;
        if (v10 == 0) {
            v2 = *src;
            v8 = ptr->field_20;
            if (v8 != 0) {
                result = &off_1401109B9;
                a2 = &off_1401109A9;
                if (v2 != 0) a2 = result;
                result = v2;
                v5 = result + result*8;
                v5 += 16;
                sub_140013110(v8, a2, v5);
                src2 = 1;
                if (result == 0) {
                    *(__int64 *)ptr = (__int64)(0);
                    ptr->field_8 = v2;
                    src2 = 0;
                }
                result = (__int64)src2;
                return result;
            }
            return result;
        } else {
            v11 = *src;
            sub_140023E98(v10, v11);
            if ((result & 1) == 0) {
                ptr = ptr->field_20;
                if (ptr != 0) {
                    a2 = &off_140117680;
                    sub_140013110(ptr, a2, 2);
                    src2 = 1;
                    if (result == 0) {
                        sub_140013110(ptr, v10, v11);
                        if (result == 0) {
                            if ((ptr->field_12 & 128) != 0) {
                                return (__int64)src2;
                            } else {
                                sub_140024D41();
                                if (result == 0) JUMPOUT(0x140023d09);
                                v2 = a2;
                                v9 = (__int64)ptr;
                                a2 = result;
                                return a2;
                            }
                        }
                    }
                    return a2;
                }
            } else {
                v_8 = a2;
                ptr = ptr->field_20;
                if (ptr != 0) {
                    v6 = src - 8;
                    sub_140018400(v6, ptr);
                    src2 = 1;
                    return (__int64)src2;
                }
            }
        }
    }
    return result;
}