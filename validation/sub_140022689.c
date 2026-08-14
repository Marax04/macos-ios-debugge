// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 __fastcall sub_140022689(__int64 a1, __int64 *a2) {
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 i;
    __int64 *result;
    int v4;
    __int64 *src;
    __int64 v6;
    int v2;

    ptr = (struct Struct_1_t *)a2;
    v3 = *(a2 + 8);
    i = a2[2];
    if (i < v3) {
        result = ptr->field_0;
        if (*(result + i) != 117) {
            v4 = 0;
        } else {
            ++i;
            ptr->field_10 = i;
            v4 = 1;
        }
        if (i >= v3) JUMPOUT(0x140022736);
        src = ptr->field_0;
        result = *(src + i);
        result += 208;
        if (result >= 10) JUMPOUT(0x140022736);
        ++i;
        ptr->field_10 = i;
        if (result == 0) JUMPOUT(0x14002270b);
        v6 = 10;
        do {
            if (v3 == i) JUMPOUT(0x140022722);
            v2 = *(src + i);
            v2 += 208;
            if (v2 > 9) JUMPOUT(0x14002270d);
            ++i;
            ptr->field_10 = i;
            result = (__int64 *)((__int64)(__int64)(__int64)result * v6); /* unsigned; high half in a2 */;
            if ((0 /* overflow check on (i + 1) */)) JUMPOUT(0x140022736);
            result = (__int64 *)((__int64)result + (__int64)a2);
            if ((result < 0)) JUMPOUT(0x140022736);
        } while (true);
    }
    return (__int64)result;
}