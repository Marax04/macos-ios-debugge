__int64 sub_1400F1D90();
__int64 sub_1400F2808();
__int64 sub_14002EDF0();
__int64 sub_140032CFE();
__int64 off_140108180();
__int64 off_140108188();
extern __int64 off_140112EA6;

__int64 __fastcall sub_140032BE0(int a1, int a2, int a3, __int64 a4) {
    int arg_1000;
    int arg_1020;
    int arg_102c;
    int arg_1030;
    int arg_ff0;
    int arg_ff8;
    int v_20;
    int v_28;
    int v_30;
    char *str;
    __int64 v4;
    __int64 v3;
    __int64 v7;
    __int64 v2;
    __int64 v5;
    __int64 v6;
    __int64 v1;

    sub_1400F1D90(0x10B8);
    arg_1030 = -2;
    v4 = a2;
    v3 = a1;
    arg_102c = a2;
    v7 = 0;
    v2 = str - 64;
    sub_1400F2808(v2, 0, 0x1000);
    a1 = 0x1200;
    if ((v4 & 0x10000000) != 0) {
        v5 = &off_140112EA6;
        off_140108180(v5);
        if (v1 == 0) {
            v7 = 0;
        } else {
            v7 = v1;
            v4 &= 0xEFFFFFFF;
            arg_102c = v4;
            a1 = 0x1A00;
        }
    }
    v_20 = v2;
    v_30 = 0;
    v_28 = 0x800;
    off_140108188(0x1200, v7, v4, 0);
    if (v1 == 0) JUMPOUT(0x140032ea4);
    v4 = v1;
    if (v1 >= 0x801) JUMPOUT(0x14003317a);
    arg_1020 = v3;
    sub_14002EDF0(0, v4);
    if (v1 == 0) JUMPOUT(0x140033191);
    arg_ff0 = v4;
    arg_ff8 = v1;
    arg_1000 = 0;
    v6 =  + v4*2 - 64;
    v6 += (__int64)str;
    v4 = 0;
    return sub_140032CFE();
}