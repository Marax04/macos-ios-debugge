// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27FC();
__int64 sub_140006A90();
__int64 sub_140006B86();
extern __int64 off_1401091F1;

__int64 __fastcall sub_140006A95(int *a1) {
    int arg_670;
    __int64 v11;
    __int64 v2;
    __int64 i;
    __int64 v8;
    __int64 v7;
    __int64 v5;
    __int64 v9;
    struct Struct_1_t *result;
    __int64 v3;
    __int64 *src;
    __int64 v4;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    arg_670 = (int)a1;
    v11 = a1[78];
    a1 =  + v11*8;
    v2 = a1 + (__int64)(__int64)a1*2;
    i = -1;
    while (v2 != 0) {
        v8 = result + 24;
        v7 = result->field_8;
        v5 = result->field_10;
        v9 = v5;
        v9 -= 7;
        result = 7;
        if (v9 >= 0) v5 = result;
        v9 = -v9;
        v3 = &off_1401091F1;
        sub_1400F27FC(v3, v7, v5);
        if (result != 0) v9 = result;
        result = (v9 < 0) ? 1 : 0;
        a1 = (v9 > 0) ? 1 : 0;
        a1 = (int *)((__int64)a1 - (__int64)result);
        v2 -= 24;
        ++i;
        result = (struct Struct_1_t *)v8;
        result = (struct Struct_1_t *)a1;
        if (a1 != 0) {
            src = (__int64 *)arg_670;
            --v4;
            if ((v4 < 0)) JUMPOUT(0x140006c68);
            src = *(src + i*8 + 632);
            return sub_140006A90();
        } else {
            return sub_140006B86();
        }
    }
    i = v11;
    return (__int64)result;
}