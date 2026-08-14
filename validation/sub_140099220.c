// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140099D90();
__int64 sub_14002EDF0();
__int64 sub_140099D89();
__int64 sub_1400994C1();
__int64 sub_1400F27F6();
__int64 sub_1400995F7();

__int64 __fastcall sub_140099220(struct Struct_1_t *a1) {
    __int64 rsp;
    int arg_13e;
    int v_2c;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    __int64 v_68;
    __int64 *arg_10;
    int *arg_110;
    __int64 *arg_18;
    __int64 *arg_8;
    __int64 *dst;
    __int64 v13;
    __int64 v7;
    __int64 v9;
    __int64 v10;
    __int64 i;
    __int64 v8;
    __int64 v2;
    __int64 *dst2;
    int v11;
    __int64 v5;
    __int64 *dst3;
    __int64 v6;

    dst = a1->field_0;
    v13 = a1->field_8;
    if (dst == 0) {
        v7 = ((__int64 *)a1)[3];
        return sub_140099D90();
    } else {
        v9 = ((__int64 *)a1)[4];
        if (v13 == 0) {
            sub_14002EDF0(0, 320);
            if (dst2 == 0) JUMPOUT(0x140099dd2);
            *dst2 = 0;
            *dst = dst2;
            *(dst + 8) = 0;
            arg_13e = 1;
            arg_110 = (int *)v9;
            arg_8 = 0;
            arg_10 = 2;
            arg_18 = 0;
            v10 = 0;
            return sub_140099D89();
        } else {
            v10 = ((__int64 *)a1)[3];
            i = arg_13e;
            v_68 = (__int64)dst;
            if (i >= 11) {
                v8 = ((__int64 *)a1)[2];
                sub_14002EDF0(0, 320);
                v_38 = (__int64)dst2;
                v_40 = v9;
                if (v10 >= 5) JUMPOUT(0x1400993fe);
                if (dst2 == 0) JUMPOUT(0x140099dd2);
                *dst2 = 0;
                v2 = arg_13e;
                v2 -= 5;
                arg_13e = v2;
                if (v2 >= 12) JUMPOUT(0x140099de1);
                dst2 = 112;
                v_30 = (__int64)dst2;
                v_2c = 4;
                v11 = 128;
                dst2 = 288;
                a1 = 104;
                return sub_1400994C1();
            } else {
                v5 = v10 + 1;
                dst3 =  + v10*4 + 272;
                dst3 += v13;
                if (v5 <= i) {
                    dst2 = v13 + 272;
                    a1 = dst2 + v5*4;
                    v2 = i;
                    v2 -= v10;
                    v6 =  + v2*4;
                    sub_1400F27F6(a1, 292, v6);
                    arg_110[v10] = v9;
                    dst2 =  + v10*2;
                    dst2 += v10;
                    dst3 =  + (__int64)(__int64)dst2*8 + 8;
                    dst3 += v13;
                    dst2 = v5 + v5*2;
                    a1 =  + (__int64)(__int64)dst2*8 + 8;
                    a1 += v13;
                    v2 <<= 3;
                    v9 = v2 + v2*2;
                    sub_1400F27F6(a1, dst3, v9);
                } else {
                    *dst3 = v9;
                }
                ++i;
                dst2 =  + v10*2;
                dst2 += v10;
                arg_8[(__int64)dst2] = 0;
                arg_10[(__int64)dst2] = 2;
                arg_18[(__int64)dst2] = 0;
                arg_13e = i;
                a1 = 0x8000000000000000;
                dst3 = rsp + 144;
                dst2 = (__int64 *)v13;
                return sub_1400995F7();
            }
        }
    }
}