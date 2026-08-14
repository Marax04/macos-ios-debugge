// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int16 field_10; // offset 16
    __int64 field_12; // offset 18
};

__int64 sub_140018FF0();
__int64 sub_140050019();
extern __int64 off_1401109A8;
extern __int64 off_14011AB0E;
extern __int64 off_14010B408;
extern __int64 off_140053F90;
extern __int64 off_140115F19;
extern __int64 off_140050390;
extern __int64 off_140115F0F;
extern __int64 off_1400545E0;
extern __int64 off_140115F0B;
extern __int64 off_14000E460;
extern __int64 off_140115F05;
extern __int64 off_140115F08;
extern __int64 off_14011530C;

__int64 __fastcall sub_14004FD40(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_18;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    int v_9f;
    int v_a0;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    int v_d0;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v4;
    __int64 result;
    int v5;
    __m128i xmm0;
    __int64 v2;
    __int64 v6;

    ptr = (struct Struct_1_t *)a2;
    v7 = arg_8;
    v4 = a1[2];
    a1 = *a2;
    result = arg_8;
    a2 = &off_1401109A8;
    v5 = 1;
    ((__int64 (*)())(arg_18))();
    a1 = (int *)result;
    if (v4 != 0) {
        result = 1;
        if (a1 == 0) {
            if ((ptr->field_12 & 128) != 0) {
                a1 = ptr->field_0;
                result = ptr->field_8;
                a2 = &off_14011AB0E;
                v5 = 1;
                ((__int64 (*)())(arg_18))();
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    v_9f = 1;
                    xmm0 = _mm_loadu_si128((__m128i *)ptr);
                    _mm_store_si128((__m128i *)&v_c0, xmm0);
                    result = rsp + 159;
                    v_d0 = result;
                    result = ptr->field_10;
                    v_b0 = result;
                    result = rsp + 192;
                    v_a0 = result;
                    result = &off_14010B408;
                    v_a8 = result;
                    result = v7 + 24;
                    a1 = v7 + 48;
                    a2 = v7 + 96;
                    v_b8 = (int)a2;
                    a2 = &off_140053F90;
                    v_90 = (int)a2;
                    a2 = rsp + 184;
                    v_88 = (int)a2;
                    a2 = &off_140115F19;
                    v_78 = (int)a2;
                    a2 = &off_140050390;
                    v_70 = (int)a2;
                    v_68 = (int)a1;
                    a1 = &off_140115F0F;
                    v_58 = (int)a1;
                    a1 = &off_1400545E0;
                    v_50 = (int)a1;
                    v_48 = result;
                    result = &off_140115F0B;
                    v_38 = result;
                    result = &off_14000E460;
                    v_30 = result;
                    v_28 = v7;
                    v_80 = 12;
                    v_60 = 10;
                    v_40 = 4;
                    v_20 = 3;
                    a2 = &off_140115F05;
                    v2 = &off_140115F08;
                    a1 = rsp + 160;
                    sub_140018FF0(a1, a2, 3, v2);
                    if (result == 0) JUMPOUT(0x14004fff3);
                    result = 1;
                }
                if (v4 != 1) JUMPOUT(0x140050019);
            } else {
                result = v7 + 24;
                a1 = v7 + 48;
                a2 = v7 + 96;
                v_a0 = (int)a2;
                a2 = &off_140053F90;
                v_90 = (int)a2;
                a2 = rsp + 160;
                v_88 = (int)a2;
                a2 = &off_140115F19;
                v_78 = (int)a2;
                a2 = &off_140050390;
                v_70 = (int)a2;
                v_68 = (int)a1;
                a1 = &off_140115F0F;
                v_58 = (int)a1;
                a1 = &off_1400545E0;
                v_50 = (int)a1;
                v_48 = result;
                result = &off_140115F0B;
                v_38 = result;
                result = &off_14000E460;
                v_30 = result;
                v_28 = v7;
                v_80 = 12;
                v_60 = 10;
                v_40 = 4;
                v_20 = 3;
                a2 = &off_140115F05;
                v6 = &off_140115F08;
                sub_140018FF0(ptr, a2, 3, v6);
                if (v4 != 1) {
                    return sub_140050019();
                }
            }
            a1 = (int *)result;
            result = 1;
            if (a1 == 0) {
                a1 = ptr->field_0;
                result = ptr->field_8;
                a2 = &off_14011530C;
                v5 = 1;
                ((__int64 (*)())(arg_18))();
            }
            return v5;
        }
        return v5;
    }
    return result;
}