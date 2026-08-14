// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_140042BEE();
__int64 off_1401081D8();

__int64 __fastcall sub_140042B20(__int64 *a1, int a2, __int64 a3, int a4) {
    int arg_70;
    int v_10;
    int v_20;
    char *dst;
    __int64 v2;
    __int64 *src;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v10;
    __int64 v9;
    __int64 i;
    __int64 v5;
    __int64 result;

    *dst = -2;
    v_10 = a4;
    v2 = a3;
    src = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    do {
        ptr2 = src + 360;
        v10 = *(src + 978);
        v9 = v10 * 56;
        i = -1;
        while (v9 != 0) {
            v5 = ptr2->field_28;
            a4 = ptr2->field_30;
            v_20 = 1;
            a2 = arg_70;
            off_1401081D8(v_10, a2, v5, a4);
            ++i;
            if (result == 1) {
                --v2;
                if ((v2 < 0)) JUMPOUT(0x140042be5);
                src = *(src + i*8 + 984);
            }
            if (result != 2) {
                ptr2 += 56;
                v9 -= 56;
                return sub_140042BEE();
            }
            result = 0;
            ptr->field_8 = src;
            ptr->field_10 = v2;
            ptr->field_18 = i;
            *(__int64 *)ptr = (__int64)(result);
            return result;
        }
        i = v10;
        return result;
    } while (true);
}