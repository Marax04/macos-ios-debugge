// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_14008D400;
extern __int64 off_140119E18;
extern __int64 off_14008D640;
extern __int64 off_140117C00;
extern __int64 off_14008D420;
extern __int64 off_14008D4A0;
extern __int64 off_140117BD0;

__int64 __fastcall sub_1400BD380(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    __int64 v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    __int64 v_60;
    __int64 v_68;
    __int64 v_70;
    __int64 v_78;
    int v_80;
    __int64 *result;
    __int64 v2;
    __int64 v3;
    __int64 v_cap;

    result = *a1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    v2 = *result;
    v3 = v2 - 3;
    v_cap = 2;
    if (v3 >= 2) v_cap = v3;
    if (v_cap == 0) {
        result += 4;
        v_28 = (__int64)result;
        result = rsp + 40;
        v_60 = (__int64)result;
        result = &off_14008D400;
        v_68 = (__int64)result;
        result = &off_140119E18;
    } else {
        if (v_cap != 1) {
            v_28 = (__int64)result;
            result = rsp + 40;
            v_60 = (__int64)result;
            result = &off_14008D640;
            v_68 = (__int64)result;
            result = &off_140117C00;
        } else {
            v_cap = result + 16;
            v_80 = v_cap;
            result += 8;
            v_28 = (__int64)result;
            result = rsp + 40;
            v_60 = (__int64)result;
            result = &off_14008D420;
            v_68 = (__int64)result;
            result = rsp + 128;
            v_70 = (__int64)result;
            result = &off_14008D4A0;
            v_78 = (__int64)result;
            result = &off_140117BD0;
            v_30 = (__int64)result;
            v_38 = 2;
            v_50 = 0;
            result = rsp + 96;
            v_40 = (__int64)result;
            v_48 = 2;
            v_cap = rsp + 48;
            sub_140011760(v_cap, a2, v2, v3);
            return (__int64)result;
        }
    }
    v_30 = (__int64)result;
    v_38 = 1;
    v_50 = 0;
    result = rsp + 96;
    v_40 = (__int64)result;
    v_48 = 1;
    v_cap = rsp + 48;
    return sub_140011760(v_cap);
}