// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_140013110();
__int64 sub_140024D41();
extern __int64 off_1401109D2;
extern __int64 off_1401109A9;
extern __int64 off_1401109B9;

__int64 __fastcall sub_140022D6B(int *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v6;
    __int64 v5;
    __int64 v11;
    __int64 v8;
    __int64 v7;
    __int64 result;
    __int64 v2;
    __int64 v10;
    __int64 v9;

    ptr = (struct Struct_1_t *)a1;
    src = *a1;
    if (src == 0) {
        v6 = ptr->field_20;
        if (v6 != 0) {
            a2 = &off_1401109D2;
            v5 = 1;
            return sub_140013110();
        }
    } else {
        v11 = ptr->field_8;
        v8 = ptr->field_10;
        if (v8 >= v11) {
            v7 = ptr->field_20;
            if (v7 != 0) {
                a2 = &off_1401109A9;
                sub_140013110(v7, a2, 16);
                src = 1;
                if (result == 0) {
                    *(__int64 *)ptr = (__int64)(0);
                    ptr->field_8 = 0;
                    src = 0;
                }
                result = (__int64)src;
                return result;
            }
            return result;
        } else {
            v2 = *(src + v8);
            v10 = v8 + 1;
            ptr->field_10 = v10;
            sub_140024D41();
            if (result == 0) {
                result = ptr->field_18;
                ++result;
                ptr->field_18 = result;
                if (result <= 500) JUMPOUT(0x140022e67);
                v9 = ptr->field_20;
                if (v9 != 0) {
                    a2 = &off_1401109B9;
                    sub_140013110(v9, a2, 25);
                    src = 1;
                    if (result == 0) {
                        *(__int64 *)ptr = (__int64)(0);
                        ptr->field_8 = 1;
                        return (__int64)src;
                    }
                    return (__int64)src;
                }
                return (__int64)src;
            } else {
                v2 = ptr->field_20;
                if (v2 != 0) {
                    v5 = a2;
                    a2 = result;
                    return a2;
                }
            }
        }
    }
    return result;
}