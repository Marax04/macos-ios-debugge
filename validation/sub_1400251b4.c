// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_140013110();
__int64 sub_140023492();
extern __int64 off_1401109D2;
extern __int64 off_140110AC1;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;
extern __int64 off_140110ABE;

__int64 __fastcall sub_1400251B4(size_t *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v7;
    __int64 v10;
    int v5;
    __int64 i;
    __int64 v9;
    __int64 v4;
    __int64 v8;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    if (result == 0) {
        v7 = ptr->field_20;
        if (v7 != 0) {
            v10 = &off_1401109D2;
            v5 = 1;
            return sub_140013110();
        }
    } else {
        i = ptr->field_10;
        if (i < ptr->field_8) {
            result = *(result + i);
            ++i;
            ptr->field_10 = i;
            if (result == 78) {
                v9 = ptr->field_20;
                if (v9 != 0) {
                    a2 = &off_140110AC1;
                    sub_140013110(v9, a2, 5);
                    v4 = 1;
                    if (result == 0) {
                        v4 = 0;
                    }
                    result = (__int64 *)v4;
                    return (__int64)result;
                }
            } else {
                if (result == 79) {
                    result = ptr->field_18;
                    ++result;
                    ptr->field_18 = result;
                    if (result <= 500) JUMPOUT(0x140025309);
                    v8 = ptr->field_20;
                    if (v8 != 0) {
                        a2 = &off_1401109B9;
                        sub_140013110(v8, a2, 25);
                        v4 = 1;
                        if (result == 0) {
                            *(__int64 *)ptr = (__int64)(0);
                            ptr->field_8 = 1;
                            return v4;
                        }
                        return v4;
                    }
                    return v4;
                } else {
                    if (result != 82) {
                        v6 = ptr->field_20;
                        if (v6 != 0) {
                            a2 = &off_1401109A9;
                            sub_140013110(v6, a2, 16);
                            v4 = 1;
                            if (result == 0) {
                                *(__int64 *)ptr = (__int64)(0);
                                ptr->field_8 = 0;
                                return v4;
                            }
                            return v4;
                        }
                        return v4;
                    } else {
                        sub_140023492(ptr, 0);
                        v4 = 1;
                        if (result == 0) {
                            v4 = ptr->field_20;
                            if (v4 != 0) {
                                a2 = &off_140110ABE;
                                sub_140013110(v4, a2, 3);
                                if (result == 0) {
                                    sub_140023492(ptr, 0);
                                    return a2;
                                }
                                return a2;
                            }
                            return a2;
                        }
                        return a2;
                    }
                }
            }
            return a2;
        }
        return a2;
    }
    return (__int64)result;
}