// inferred from 2 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140013110();

__int64 __fastcall sub_14001B170(__int64 a1, int *a2,struct Struct_1_t *a3) {
    __int64 v3;
    __int64 v4;
    __int64 v8;
    __int64 *src;
    __int64 result;
    __int64 i;
    __int64 v2;
    __int64 *src2;
    int v9;
    __int64 v7;

    v3 = (__int64)a2;
    v4 = a1;
    v8 = a1 + a2;
    a1 = a3->field_0;
    src = a3->field_8;
    result = 0;
    while (result != v3) {
        a2 = v4 + result;
        i = v4 + result;
        ++i;
        v2 = result;
        src2 = (__int64 *)a2;
        do {
            v9 = *src2;
            v7 = 1;
            src2 = (__int64 *)i;
            v2 += v7;
            i = 0;
            i = (src2 != v8) ? 1 : 0;
            i += (__int64)src2;
        } while (src2 != v8);
        v3 -= result;
        v4 += result;
        if (result != 0) {
            result = *(src + 24);
            a2 = (int *)v4;
            a3 = (struct Struct_1_t *)v3;
            JUMPOUT(result);
        }
        a1 = (__int64)a3;
        a2 = (int *)v4;
        a3 = (struct Struct_1_t *)v3;
        return sub_140013110();
    }
    result = v3;
    return result;
}