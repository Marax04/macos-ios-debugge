// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140022D6B();
__int64 sub_140023492();
__int64 sub_1400233F1();
__int64 sub_140023ADD();
__int64 sub_140013110();
extern __int64 off_140116F20;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_1400232AF(__int64 *a1) {
    int v_7;
    int v_8;
    char *src;
    __int64 *src2;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    __int64 v10;
    __int64 v11;
    __int64 v6;
    __int64 i;
    __int64 result;
    __int64 v9;
    __int64 v7;

    src2 = *a1;
    if (src2 != 0) {
        ptr = (struct Struct_1_t *)a1;
        v5 = 0;
        v2 = src - 8;
        v10 = &off_140116F20;
        v11 = 0;
        do {
            v6 = ptr->field_8;
            i = ptr->field_10;
            --v11;
            if ((v11 < 0)) {
                if (i >= v6) {
                    sub_140022D6B(ptr);
                    if (result == 0) {
                        src2 = ptr->field_0;
                        result = v5;
                        return result;
                    }
                    v5 = 1;
                    return v5;
                }
                result = *(src2 + i);
                if (result == 75) {
                    ++i;
                    ptr->field_10 = i;
                    sub_140023492(ptr, 0);
                    return i;
                }
                if (result != 76) {
                    return i;
                }
                ++i;
                ptr->field_10 = i;
                sub_1400233F1(v2, ptr, v6);
                if (v_8 == 0) {
                    i = *src;
                    sub_140023ADD(ptr, i);
                    return i;
                }
                v2 = v_7;
                a1 = ptr->field_20;
                if (a1 == 0) JUMPOUT(0x1400233e5);
                v9 = &off_1401109B9;
                i = &off_1401109A9;
                if (v2 != 0) i = v9;
                result = v2;
                v7 = v9 + v9*8;
                v7 += 16;
                sub_140013110(a1, i, v7);
                if (result == 0) JUMPOUT(0x1400233e5);
                return v7;
            }
            a1 = ptr->field_20;
            if (a1 == 0) {
                return (__int64)a1;
            }
            sub_140013110(a1, v10, 2);
            if (result == 0) {
                src2 = ptr->field_0;
                if (src2 == 0) {
                    return (__int64)src2;
                }
                v6 = ptr->field_8;
                i = ptr->field_10;
                return i;
            }
            return i;
        } while (src2 != 0);
        return i;
    }
    v5 = 0;
    return result;
}