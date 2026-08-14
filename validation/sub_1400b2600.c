// inferred from 2 accesses on `a3`
struct Struct_1_t {
    char _pad_start[96];
    __int64 field_60; // offset 96
    char _pad_60[12];
    __int64 field_74; // offset 116
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    int field_8; // offset 8
    __int64 field_C; // offset 12
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[4];
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

__int64 sub_14006B9D0();
__int64 sub_14006C940();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();
__int64 sub_14006B5E0();
__int64 sub_1400F1D90();
__int64 sub_1400B2F5A();
__int64 sub_1400972B0();
__int64 sub_1400F3360();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400B2600(int *a1, __int64 a2,struct Struct_1_t *a3, __int64 a4) {
    __int64 rsp;
    int arg_8;
    int v_18480;
    int v_18490;
    int v_184a0;
    int v_184b0;
    int v_184c0;
    int v_184d0;
    int v_184e0;
    int v_184f0;
    int v_18500;
    int v_18510;
    int v_20;
    int v_28;
    int v_30;
    int v_31;
    int v_32;
    int v_33;
    int v_34;
    int v_35;
    int v_36;
    int v_37;
    int v_38;
    int v_39;
    int v_3a;
    int v_3b;
    int v_3c;
    int v_3d;
    int v_3e;
    int v_3f;
    int v_40;
    int v_41;
    int v_42;
    int v_43;
    int v_44;
    int v_45;
    int v_46;
    int v_47;
    int v_48;
    int v_49;
    int v_4a;
    int v_4b;
    int v_4c;
    int v_4d;
    int v_4e;
    int v_4f;
    int v_50;
    int v_51;
    int v_52;
    int v_53;
    int v_54;
    int v_55;
    int v_56;
    int v_57;
    int v_58;
    int v_59;
    int v_5a;
    int v_5b;
    int v_5c;
    int v_5d;
    int v_5e;
    int v_5f;
    int v_60;
    int v_61;
    int v_62;
    int v_63;
    int v_64;
    int v_65;
    int v_66;
    int v_67;
    int v_68;
    int v_69;
    int v_6a;
    int v_6b;
    int v_6c;
    int v_6d;
    int v_6e;
    int v_6f;
    int v_88;
    int v_b8;
    int v_e0;
    int v_e8;
    int v_f0;
    int v_f8;
    __int64 v2;
    __int64 v9;
    __int64 v4;
    struct Struct_3_t *ptr2;
    __int64 v3;
    __int64 v10;
    __int64 v7;
    __m128i xmm0;
    __m128i xmm1;
    int v11;
    __int64 v6;
    __int64 result;
    struct Struct_2_t *ptr;
    __m128i xmm15;
    __m128i xmm14;
    __m128i xmm13;
    __m128i xmm12;
    __m128i xmm11;
    __m128i xmm10;
    __m128i xmm9;
    __m128i xmm8;
    __m128i xmm7;
    __m128i xmm6;

    if (a4 != 0) {
        v2 = v_e0;
        if (v2 != 0) {
            v9 = a4;
            v4 = a2;
            ptr2 = (struct Struct_3_t *)a1;
            v3 = v_f0;
            v10 = v_e8;
            a1 = rsp + 48;
            v7 = (__int64)a3;
            sub_14006B9D0(a1, a3, v10, v3);
            a1 = rsp + 116;
            sub_14006C940(a1, v7, v10, v3);
            if (v2 >= 0) {
                sub_14002EDF0(0, v2);
                if (result == 0) {
                    sub_1400F3326(1, v2);
                } else {
                    v3 = result;
                    sub_1400F27F0(result, v9, v2);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_40);
                    _mm_store_si128((__m128i *)&v_60, xmm1);
                    _mm_store_si128((__m128i *)&v_50, xmm0);
                    a1 = rsp + 80;
                    a2 = rsp + 116;
                    sub_14006B5E0(a1, a2, result, v2);
                    v_50 = 0;
                    v_51 = 0;
                    v_52 = 0;
                    v_53 = 0;
                    v_54 = 0;
                    v_55 = 0;
                    v_56 = 0;
                    v_57 = 0;
                    v_58 = 0;
                    v_59 = 0;
                    v_5a = 0;
                    v_5b = 0;
                    v_5c = 0;
                    v_5d = 0;
                    v_5e = 0;
                    v_5f = 0;
                    v_60 = 0;
                    v_61 = 0;
                    v_62 = 0;
                    v_63 = 0;
                    v_64 = 0;
                    v_65 = 0;
                    v_66 = 0;
                    v_67 = 0;
                    v_68 = 0;
                    v_69 = 0;
                    v_6a = 0;
                    v_6b = 0;
                    v_6c = 0;
                    v_6d = 0;
                    v_6e = 0;
                    v_6f = 0;
                    v7 = 0xFFFFFFFF;
                    if (v2 < v7) v7 = v2;
                    v10 = v2;
                    v10 += 16;
                    if ((v10 >= 0)) {
                        sub_14002EDF0(0, v10);
                        if (result == 0) {
                            sub_1400F3326(1, v10);
                            sub_1400F1D90(0x18528);
                            _mm_store_si128((__m128i *)&v_18510, xmm15);
                            _mm_store_si128((__m128i *)&v_18500, xmm14);
                            _mm_store_si128((__m128i *)&v_184f0, xmm13);
                            _mm_store_si128((__m128i *)&v_184e0, xmm12);
                            _mm_store_si128((__m128i *)&v_184d0, xmm11);
                            _mm_store_si128((__m128i *)&v_184c0, xmm10);
                            _mm_store_si128((__m128i *)&v_184b0, xmm9);
                            _mm_store_si128((__m128i *)&v_184a0, xmm8);
                            _mm_store_si128((__m128i *)&v_18490, xmm7);
                            _mm_store_si128((__m128i *)&v_18480, xmm6);
                            v_88 = (int)a3;
                            v11 = a3->field_74;
                            v6 = a3->field_60;
                            v_60 = v6;
                            v_50 = v10;
                            v_b8 = (int)a1;
                            if ((v11 & 16) != 0) JUMPOUT(0x1400b29d5);
                            result = 1;
                            v_48 = v6;
                            v2 = 0;
                            return sub_1400B2F5A();
                        } else {
                            ptr = (struct Struct_2_t *)result;
                            result = v_f8;
                            *(__int64 *)ptr = (__int64)(result);
                            ptr->field_8 = 1;
                            ptr->field_C = v7;
                            a1 = (int *)ptr;
                            a1 += 16;
                            sub_1400F27F0(a1, v3, v2);
                            v_20 = v10;
                            v_28 = 0x40000040;
                            a2 = rsp + 256;
                            sub_1400972B0(v4, a2, 8, ptr);
                            if ((result & 1) == 0) {
                                ptr2->field_8 = v10;
                                *(__int64 *)ptr2 = (__int64)(12);
                            } else {
                                a1 = (int *)result;
                                a1 = (int *)((__int64)(__int64)a1 >> 32);
                                /* shrd $16, %(__int64)a1, %result */;
                                *(__int64 *)ptr2 = (__int64)(8);
                                ptr2->field_4 = result;
                            }
                            v4 = off_140108030;
                            ((__int64 (*)())v4)(a1);
                            v2 = off_140108038;
                            ((__int64 (*)())v2)(result, 0, ptr);
                            ((__int64 (*)())v4)();
                            ((__int64 (*)())v2)(result, 0, v3);
                            v_30 = 0;
                            v_31 = 0;
                            v_32 = 0;
                            v_33 = 0;
                            v_34 = 0;
                            v_35 = 0;
                            v_36 = 0;
                            v_37 = 0;
                            v_38 = 0;
                            v_39 = 0;
                            v_3a = 0;
                            v_3b = 0;
                            v_3c = 0;
                            v_3d = 0;
                            v_3e = 0;
                            v_3f = 0;
                            v_40 = 0;
                            v_41 = 0;
                            v_42 = 0;
                            v_43 = 0;
                            v_44 = 0;
                            v_45 = 0;
                            v_46 = 0;
                            v_47 = 0;
                            v_48 = 0;
                            v_49 = 0;
                            v_4a = 0;
                            v_4b = 0;
                            v_4c = 0;
                            v_4d = 0;
                            v_4e = 0;
                            v_4f = 0;
                        }
                    } else {
                        sub_1400F3360();
                        arg_8 = 0;
                        *a1 = 12;
                    }
                    return arg_8;
                }
                return arg_8;
            }
            return arg_8;
        }
    }
    return result;
}