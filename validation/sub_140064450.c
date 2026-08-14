// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_140064DC0();
__int64 sub_140064FE0();
__int64 sub_140064210();
__int64 sub_140064A58();

__int64 __fastcall sub_140064450(int *a1) {
    __int64 rsp;
    int v_30;
    int v_38;
    int v_40;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_aa;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v7;
    int v12;
    __int64 v8;
    __int64 v3;
    __int64 v9;
    __int64 v10;
    __int64 *i;
    __int64 v6;
    __int64 v2;
    __int64 v1;

    sub_14002EDF0(0, 48);
    if (v1 == 0) {
        sub_1400F3340(8, 48);
        ptr = (struct Struct_1_t *)v3;
        v4 = (__int64)a1;
        a1 = rsp + 48;
        sub_140064DC0(a1);
        v7 = v_30;
        v12 = v_38;
        if (v7 != 3) JUMPOUT(0x1400645c3);
        v8 = ptr->field_18;
        if (v8 == 0) JUMPOUT(0x140064602);
        a1 = ptr->field_10;
        if (*a1 != 58) JUMPOUT(0x140064602);
        ++a1;
        --v8;
        ptr->field_10 = a1;
        ptr->field_18 = v8;
        a1 = rsp + 48;
        sub_140064FE0(a1, ptr);
        v3 = v_30;
        v9 = v_38;
        if (v3 != 3) JUMPOUT(0x140064631);
        v10 = ptr->field_18;
        if (v10 == 0) JUMPOUT(0x1400646c7);
        i = ptr->field_10;
        if (*i != 58) JUMPOUT(0x1400646c7);
        ++i;
        --v10;
        ptr->field_10 = i;
        ptr->field_18 = v10;
        v_90 = 1;
        v_98 = 2;
        v_a0 = 2;
        v_a8 = 0x3000;
        v_aa = 57;
        a1 = rsp + 48;
        v3 = rsp + 144;
        sub_140064210(a1, v3, ptr);
        v3 = v_30;
        a1 = (int *)v_38;
        v6 = v_40;
        if (v3 != 3) JUMPOUT(0x140064808);
        if (v6 == 1) JUMPOUT(0x14006481f);
        if (v6 == 0) JUMPOUT(0x140064d97);
        if (*a1 != 43) JUMPOUT(0x14006483f);
        ++a1;
        v9 = v6 - 1;
        v2 = v9;
        if ((v6 < 4)) JUMPOUT(0x14006484e);
        return sub_140064A58();
    } else {
        return v2;
    }
}