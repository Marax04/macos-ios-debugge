// inferred from 4 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14002EDF0();
__int64 sub_1400562EF();
__int64 sub_140056258();
extern __int64 off_140121EE4;
extern __int64 off_140009780;
extern __int64 off_1401163A0;

__int64 __fastcall sub_140055FA0(struct Struct_1_t *a1, __int64 a2, int a3) {
    __int64 rsp;
    int v_28;
    int v_60;
    int v_68;
    __int64 v1;
    __int64 *src;
    __int64 v3;
    __int64 v5;
    __int64 v6;
    __int64 v2;
    __int64 v4;

    v1 = a1->field_0;
    a3 = 0x8000000000000001;
    a3 += v1;
    v1 >>= 63;
    v1 &= a3;
    src = &off_140121EE4;
    v1 = *(src + v1*4);
    v1 += (__int64)src;
    JUMPOUT(v1);
    v_28 = (int)a1;
    v1 = 0;
    if (!__OFSUB(v1, a1->field_18)) {
        v3 = a1->field_28;
        if (v3 == 0) JUMPOUT(0x14005623b);
        v5 = a2;
        v6 = a1->field_20;
        v2 = v3;
        v2 <<= 4;
        sub_14002EDF0(0, v2);
        if (v1 == 0) JUMPOUT(0x1400563d2);
        v4 = v1;
        if (v3 != 1) JUMPOUT(0x140056298);
        v1 = 0;
        return sub_1400562EF();
    } else {
        v1 = rsp + 40;
        v_60 = v1;
        v1 = &off_140009780;
        v_68 = v1;
        v1 = &off_1401163A0;
        return sub_140056258();
    }
}