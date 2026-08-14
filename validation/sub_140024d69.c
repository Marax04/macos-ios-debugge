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
__int64 sub_140023ADD();
extern __int64 off_1401109D2;
extern __int64 off_140110AB8;
extern __int64 off_140116F20;
extern __int64 off_1401109B9;
extern __int64 off_1401109A9;

__int64 __fastcall sub_140024D69(__int64 *a1) {
    int v_7;
    char *src;
    struct Struct_1_t *ptr;
    __int64 v8;
    __int64 v3;
    __int64 v6;
    __int64 *v5;
    __int64 v9;
    __int64 v11;
    __int64 i;
    __int64 v2;
    __int64 result;
    __int64 v10;
    __int64 v7;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 == 0) {
        v8 = ptr->field_20;
        if (v8 != 0) {
            v3 = &off_1401109D2;
            v6 = 1;
            return sub_140013110();
        }
    } else {
        v5 = src - 8;
        sub_140022618(v5, ptr, 71);
        if (*v5 != 1) {
            v9 = ptr->field_20;
            if (v9 == 0) JUMPOUT(0x140024e8f);
            v11 = *src;
            if (v11 == 0) JUMPOUT(0x140024ec6);
            v3 = &off_140110AB8;
            sub_140013110(v9, v3, 4);
            v5 = 1;
            if (result == 0) {
                i = 0;
                v2 = &off_140116F20;
                do {
                    if (v11 == i) JUMPOUT(0x140024ea3);
                    if (i == 0) {
                        ptr->field_28 = ptr->field_28 + 1;
                        sub_140023ADD(ptr, 1);
                        ++i;
                        result = (__int64)v5;
                        return result;
                    }
                    v10 = ptr->field_20;
                    if (v10 == 0) {
                        return v10;
                    }
                    sub_140013110(v10, v2, 2);
                    if (result == 0) {
                        return v10;
                    }
                    return v10;
                } while (result == 0);
                return v10;
            }
        } else {
            v2 = v_7;
            v7 = ptr->field_20;
            if (v7 != 0) {
                result = &off_1401109B9;
                v3 = &off_1401109A9;
                if (v2 != 0) v3 = result;
                result = v2;
                v6 = result + result*8;
                v6 += 16;
                sub_140013110(v7, v3, v6);
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