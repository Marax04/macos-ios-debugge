// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_140023BC4();
__int64 sub_140013110();
__int64 sub_140024560();
__int64 sub_140023D16();
extern __int64 off_140121174;
extern __int64 off_140110A39;
extern __int64 off_1401109A8;
extern __int64 off_14011530C;
extern __int64 off_1401109E4;
extern __int64 off_1401109A9;
extern __int64 off_1401109B9;

__int64 __fastcall sub_140023492(size_t *a1, int a2) {
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 result;
    int v2;
    int v9;
    __int64 i;
    __int64 v7;
    __int64 v8;
    int v4;

    ptr = (struct Struct_1_t *)a1;
    a1 = *a1;
    if (a1 != 0) {
        v5 = ptr->field_8;
        result = ptr->field_10;
        if (result < v5) {
            v2 = a2;
            v9 = *(a1 + result);
            a2 = result + 1;
            ptr->field_10 = a2;
            i = ptr->field_18;
            ++i;
            ptr->field_18 = i;
            if (i <= 500) {
                i = v9;
                v7 = i - 81;
                if (v7 <= 40) {
                    v8 = &off_140121174;
                    switch (v7) {
                        case 23:
                            sub_140023BC4(ptr, v9);
                            return v8;
                        default:
                            if (i == 65) {
                                if (v2 == 0) {
                                    a1 = ptr->field_20;
                                    if (a1 != 0) {
                                        a2 = &off_140110A39;
                                        sub_140013110(a1, a2, 1);
                                        v4 = 1;
                                        if (result == 0) {
                                            a1 = ptr->field_20;
                                            if (a1 != 0) {
                                                a2 = &off_1401109A8;
                                                sub_140013110(a1, a2, 1);
                                                v4 = 1;
                                                if (result == 0) {
                                                    sub_140024560(ptr);
                                                    v4 = 1;
                                                    if (result == 0) {
                                                        a1 = ptr->field_20;
                                                        if (a1 != 0) {
                                                            a2 = &off_14011530C;
                                                            sub_140013110(a1, a2, 1);
                                                            if (result == 0) {
                                                                if (v2 == 0) {
                                                                    a1 = ptr->field_20;
                                                                    if (a1 != 0) {
                                                                        a2 = &off_1401109E4;
                                                                        sub_140013110(a1, a2, 1);
                                                                        v4 = 1;
                                                                        if (result == 0) {
                                                                            if (ptr->field_0 != 0) {
                                                                                ptr->field_18 = ptr->field_18 - 1;
                                                                            }
                                                                            v4 = 0;
                                                                        }
                                                                        result = v4;
                                                                        return result;
                                                                    }
                                                                }
                                                                return result;
                                                            }
                                                            return result;
                                                        }
                                                        return result;
                                                    }
                                                }
                                                return result;
                                            }
                                            return result;
                                        }
                                        return result;
                                    }
                                }
                                return result;
                            } else {
                                if (i != 66) {
                                    a1 = ptr->field_20;
                                    if (a1 != 0) {
                                        a2 = &off_1401109A9;
                                        sub_140013110(a1, a2, 16);
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
                                    sub_140023D16(ptr, v2);
                                    return v4;
                                }
                                return v4;
                            }
                            break;
                    }
                    return v4;
                }
                return v4;
            } else {
                a1 = ptr->field_20;
                if (a1 != 0) {
                    a2 = &off_1401109B9;
                    sub_140013110(a1, a2, 25, i);
                    v4 = 1;
                    if (result == 0) {
                        *(__int64 *)ptr = (__int64)(0);
                        ptr->field_8 = 1;
                        return v4;
                    }
                    return v4;
                }
                return v4;
            }
            return v4;
        }
        return v4;
    }
    return result;
}