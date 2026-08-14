// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3326();
__int64 sub_1400F6940();

__int64 __fastcall sub_1400F6840(int *a1, __int64 a2, __int64 a3, __int64 a4) {
    int arg_40;
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v8;
    __int64 result;

    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        ptr = (struct Struct_1_t *)a1;
        a1 = (int *)arg_40;
        v6 = ptr->field_0;
        v4 = v6 + v6;
        if (a2 > v4) v4 = a2;
        a2 = 0;
        a2 = (a1 == 1) ? 1 : 0;
        a2 =  + a2*4 + 4;
        if (v4 <= a2) v4 = a2;
        v2 = ptr->field_8;
        v_28 = (int)a1;
        v_20 = a4;
        a1 = str - 24;
        sub_1400F6940(a1, v6, v2, v4);
        if (v_18 != 1) {
            v7 = v_10;
            ptr->field_8 = v7;
            *(__int64 *)ptr = (__int64)(v4);
            return v7;
        }
    }
    a1 = (int *)v_10;
    a2 = v_8;
    sub_1400F3326(a1, a2);
    ptr = (struct Struct_1_t *)a1;
    a2 = *a1;
    v8 = a2 + a2;
    v4 = 4;
    if (v8 >= 5) v4 = v8;
    v_28 = 2;
    v_20 = 2;
    a1 = str - 24;
    sub_1400F6940(a1, a2, arg_8, v4);
    if (v_18 == 1) JUMPOUT(0x1400f692e);
    result = v_10;
    ptr->field_8 = result;
    *(__int64 *)ptr = (__int64)(v4);
    return result;
}