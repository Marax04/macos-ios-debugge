// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[24];
    __int64 field_28; // offset 40
};

__int64 sub_140013110();
__int64 sub_140013590();
__int64 sub_140023BC0();
extern __int64 off_140115B90;
extern __int64 off_14011092A;
extern __int64 off_1401109A9;

int __fastcall sub_140023ADD(__int64 *a1, __int64 a2) {
    char *str;
    __int64 v3;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v6;
    __int64 v8;
    __int64 *dst;
    int result;

    v3 = a1[4];
    if (v3 != 0) {
        v7 = a2;
        ptr = (struct Struct_1_t *)a1;
        a2 = &off_140115B90;
        sub_140013110(v3, a2, 1);
        v4 = 1;
        if (result == 0) {
            if (v7 == 0) {
                v6 = &off_14011092A;
                v4 = v3;
                return sub_140013110();
            } else {
                v8 = ptr->field_28;
                v8 -= v7;
                if ((v8 >= 0)) {
                    if (v8 >= 26) JUMPOUT(0x140023b98);
                    v8 += 97;
                    dst = str + 4;
                    *dst = v8;
                    sub_140013590(dst, v3, 1);
                    return sub_140023BC0();
                } else {
                    a2 = &off_1401109A9;
                    sub_140013110(v3, a2, 16);
                    if (result == 0) {
                        *(__int64 *)ptr = (__int64)(0);
                        ptr->field_8 = 0;
                        v4 = 0;
                    }
                }
            }
        }
        result = v4;
        return result;
    }
    return result;
}