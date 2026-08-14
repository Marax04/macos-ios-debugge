// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400B03AA();

__int64 __fastcall sub_1400B02E0(int *a1, size_t a2, __int64 *a3) {
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v11;
    __int64 v2;
    __int64 *src;
    __int64 result;
    int v12;
    __int64 v9;
    __int64 v10;
    __int64 v5;
    __int64 v6;
    __int64 *v7;

    v3 = a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(8);
    if (result == 0) {
        sub_1400F3326(1, v3);
        v11 = a1[2];
        if (v11 == 0) JUMPOUT(0x1400b03dc);
        ptr = (struct Struct_1_t *)a3;
        v2 = a2;
        v3 = (__int64)a1;
        src = *(a1 + 8);
        result = (__int64)a3;
        result <<= 4;
        v12 = 0;
        v9 = 0;
        v10 =  + v9*4;
        v10 += v9;
        a1 = src + v10*8;
        a2 = *(src + v10*8 + 32);
        v10 = *(src + v10*8 + 24);
        v10 += a2;
        v5 = result;
        v6 = v2;
        do {
            if (v5 == 0) JUMPOUT(0x1400b03a0);
            v7 = (__int64 *)v6;
            v6 += 16;
            v5 -= 16;
        } while (*v7 >= v10);
        return sub_1400B03AA();
    } else {
        *(__int64 *)ptr = (__int64)(v3);
        ptr->field_8 = result;
        ptr->field_10 = v3;
        return result;
    }
}