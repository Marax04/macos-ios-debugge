// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14007B540();
__int64 sub_1400F87E0();

int __fastcall sub_14007B930(int *a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v2;
    int v8;
    int result;
    __int64 v7;
    __int64 *dst;

    src = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14007B540();
    a1 = *(src + 9);
    i = ptr->field_10;
    if (i == ptr->field_0) {
        v2 = (__int64)a1;
        v8 = result;
        sub_1400F87E0(ptr, a2, a3, 0x8000000000000004);
        a1 = (int *)v2;
        result = v8;
    }
    a1 = (int *)((__int64)(__int64)a1 << 3);
    v7 = 0x80808040201;
    v7 >>= (__int64)a1;
    dst = ptr->field_8;
    v2 = i + i*2;
    v2 <<= 4;
    *(dst + v2) = a4;
    *(dst + v2 + 8) = result;
    *(dst + v2 + 12) = a2;
    *(dst + v2 + 13) = 0x706;
    ++i;
    ptr->field_10 = i;
    return result;
}