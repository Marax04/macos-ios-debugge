// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_140013110();
__int64 sub_140022618();
__int64 sub_140025393();
__int64 sub_140023ADD();
extern __int64 off_1401109D2;
extern __int64 off_140110AB8;
extern __int64 off_140116F20;
extern __int64 off_140110ABC;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_140025049(__int64 *a1) {
    int v_7;
    char *src;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 v6;
    __int64 *v5;
    __int64 v7;
    __int64 i;
    __int64 v2;
    __int64 result;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 == 0) {
        a1 = ptr->field_20;
        if (a1 != 0) {
            v3 = &off_1401109D2;
            v6 = 1;
            return sub_140013110();
        }
    } else {
        v5 = src - 8;
        sub_140022618(v5, ptr, 71);
        if (*v5 != 1) {
            a1 = ptr->field_20;
            if (a1 == 0) {
                sub_140025393(ptr);
                v5 = (__int64 *)result;
            } else {
                v7 = *src;
                if (v7 != 0) {
                    v3 = &off_140110AB8;
                    sub_140013110(a1, v3, 4);
                    v5 = 1;
                    if (result == 0) {
                        i = 0;
                        v2 = &off_140116F20;
                        while (v7 != i) {
                            if (i == 0) {
                                ptr->field_28 = ptr->field_28 + 1;
                                sub_140023ADD(ptr, 1);
                                ++i;
                                result = (__int64)v5;
                                return result;
                            }
                            a1 = ptr->field_20;
                            if (a1 == 0) {
                                return (__int64)a1;
                            }
                            sub_140013110(a1, v2, 2);
                            if (result == 0) {
                                return (__int64)a1;
                            }
                            return (__int64)a1;
                        }
                        a1 = ptr->field_20;
                        if (a1 != 0) {
                            v3 = &off_140110ABC;
                            sub_140013110(a1, v3, 2);
                            if (result == 0) {
                                sub_140025393(ptr);
                                v5 = (__int64 *)result;
                                ptr->field_28 = ptr->field_28 - v7;
                            }
                            return (__int64)v5;
                        }
                        return (__int64)v5;
                    }
                    return (__int64)v5;
                }
                return (__int64)v5;
            }
        } else {
            v2 = v_7;
            a1 = ptr->field_20;
            if (a1 != 0) {
                result = &off_1401109B9;
                v3 = &off_1401109A9;
                if (v2 != 0) v3 = result;
                result = v2;
                v6 = result + result*8;
                v6 += 16;
                sub_140013110(a1, v3, v6);
                v5 = 1;
                if (result == 0) {
                    *(__int64 *)ptr = (__int64)(0);
                    ptr->field_8 = v2;
                    v5 = 0;
                }
                return (__int64)v5;
            }
            return (__int64)v5;
        }
        return (__int64)v5;
    }
    return result;
}