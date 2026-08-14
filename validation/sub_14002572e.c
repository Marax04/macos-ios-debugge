// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140013110();
__int64 sub_140025A9A();
__int64 sub_140025A77();
__int64 sub_140024FB6();
__int64 sub_140025A75();
__int64 sub_140022689();
extern __int64 off_140110A06;
extern __int64 off_140110A0D;
extern __int64 off_1401154BB;
extern __int64 off_140110A30;
extern __int64 off_140110A32;
extern __int64 off_1401163F2;
extern __int64 off_140110A05;

__int64 __fastcall sub_14002572E(int *a1) {
    int arg_8;
    int str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 v10;
    void *buf;
    __int64 *src;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v6;
    __int64 v11;

    ptr = (struct Struct_1_t *)a1;
    a1 = *a1;
    if (a1 != 0) {
        v3 = ptr->field_8;
        result = ptr->field_10;
        if (result < v3) {
            if (*(a1 + result) != 85) {
                v10 = 0;
            } else {
                ++result;
                ptr->field_10 = result;
                v10 = 1;
            }
            if (result < v3) {
                if (*(a1 + result) != 75) {
                    if (v10 != 0) {
                        buf = 0;
                        a1 = ptr->field_20;
                        if (a1 != 0) {
                            v3 = &off_140110A06;
                            sub_140013110(a1, v3, 7);
                            src = 1;
                            if (result != 0) JUMPOUT(0x140025a77);
                        }
                        if (buf != 0) {
                            v10 = ptr->field_20;
                            if (v10 != 0) {
                                v3 = &off_140110A0D;
                                sub_140013110(v10, v3, 8);
                                src = 1;
                                if (result != 0) JUMPOUT(0x140025a77);
                            }
                            result = 0;
                            a1 = str2 - 88;
                            *a1 = result;
                            arg_8 = v11;
                            a1[2] = buf;
                            a1[3] = v11;
                            a1[4] = result;
                            a1[5] = v11;
                            result = 0x5F0000005F;
                            a1[6] = result;
                            a1[7] = 1;
                            a1[8] = 1;
                            sub_140025A9A(a1);
                            if (result == 0) JUMPOUT(0x140025a8d);
                            if (v10 != 0) {
                                sub_140013110(v10, result, v3);
                                if (result == 0) {
                                    v7 = str2 - 16;
                                    src = str2 - 88;
                                    buf = (void *)v7;
                                    memcpy(buf, src, 72);
                                    buf = (void *)v10;
                                    do {
                                        result = (__int64)buf;
                                        src = (__int64 *)result;
                                        sub_140025A9A(v7);
                                        while (result != 0) {
                                            v8 = result;
                                            result = 0;
                                            v9 = v3;
                                            v3 = &off_1401154BB;
                                            sub_140013110(src, v3, 1);
                                            if (result == 0) {
                                                buf = 0;
                                                sub_140013110(v10, v8, v9);
                                                buf = (void *)v10;
                                            }
                                            src = 1;
                                            return sub_140025A77();
                                        }
                                        if (buf != 0) {
                                            v3 = &off_140110A30;
                                            sub_140013110(buf, v3, 2);
                                            if (result != 0) {
                                                return v3;
                                            }
                                        }
                                        a1 = ptr->field_20;
                                        if (a1 != 0) {
                                            v3 = &off_140110A32;
                                            sub_140013110(a1, v3, 3);
                                            src = 1;
                                            if (result != 0) JUMPOUT(0x140025a77);
                                        }
                                        sub_140024FB6(ptr);
                                        src = 1;
                                        if ((result & 1) != 0) JUMPOUT(0x140025a77);
                                        a1 = ptr->field_20;
                                        if (a1 != 0) {
                                            v3 = &off_1401163F2;
                                            sub_140013110(a1, v3, 1);
                                            if (result != 0) JUMPOUT(0x140025a77);
                                        }
                                        a1 = ptr->field_0;
                                        if (a1 == 0) JUMPOUT(0x1400259c3);
                                        result = ptr->field_10;
                                        if (result >= ptr->field_8) JUMPOUT(0x1400259c3);
                                        if (*(a1 + result) != 117) JUMPOUT(0x1400259c3);
                                        ++result;
                                        ptr->field_10 = result;
                                        return sub_140025A75();
                                    } while (v10 == 0);
                                    return result;
                                }
                                return result;
                            }
                            return result;
                        } else {
                        }
                    }
                } else {
                    v6 = result + 1;
                    ptr->field_10 = v6;
                    if (v6 < v3) {
                        if (*(a1 + v6) != 67) {
                            src = str2 - 16;
                            sub_140022689(src, ptr);
                            buf = *src;
                            if (buf == 0) JUMPOUT(0x140025a01);
                            v11 = str;
                            if (v11 == 0) JUMPOUT(0x140025a48);
                            if (arg_8 != 0) JUMPOUT(0x140025a48);
                        } else {
                            result += 2;
                            ptr->field_10 = result;
                            v11 = 1;
                            buf = &off_140110A05;
                        }
                        if (v10 != 0) {
                            return (__int64)buf;
                        }
                        return (__int64)buf;
                    }
                    return (__int64)buf;
                }
                return (__int64)buf;
            }
            return (__int64)buf;
        }
        return (__int64)buf;
    }
    return result;
}