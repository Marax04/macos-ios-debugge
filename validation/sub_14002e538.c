// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[280333124];
    __int64 field_10B58B4C; // offset 0x10B58B4C
};

__int64 __fastcall sub_14002E538(__int64 a1) {
    int v2;
    struct Struct_1_t *result;

    v2 = 0;
    *(__int64 *)result = (__int64)(result->field_0 + result);
    result->field_10B58B4C = result->field_10B58B4C + result;
    result += 0;
    *(__int64 *)(result - 117) = (__int64)(*(__int64 *)(result - 117) + a1);
    /* popf  */;
    return (__int64)result;
}