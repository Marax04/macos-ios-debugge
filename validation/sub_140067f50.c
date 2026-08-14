// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400682A0();
__int64 sub_1400680A8();
__int64 sub_1400680A3();
__int64 sub_14006828C();

__int64 __fastcall sub_140067F50(__int64 *a1,struct Struct_1_t *a2, __int64 a3) {
    __int64 rsp;
    int v_58;
    char *str;
    struct Struct_2_t *ptr;
    __int64 *dst;
    __int64 v8;
    __int64 v1;
    __int64 v6;
    __int64 v2;
    __int64 v3;
    __int64 v5;

    ptr = (struct Struct_2_t *)a3;
    dst = a1;
    v8 = ((__int64 *)a2)[3];
    v1 = a2->field_0;
    v6 = a2->field_8;
    if (v8 == 0) {
        if (v1 == 0) JUMPOUT(0x14006805f);
        if (v6 != 0) JUMPOUT(0x1400680a3);
    } else {
        if (v8 != 1) {
            a1 = (v8 == v6) ? 1 : 0;
            if ((v1 & (__int64)a1) == 0) JUMPOUT(0x14006809b);
        } else {
            if (v1 == 0) {
                v2 = ((__int64 *)a2)[2];
                v2 += 24;
                a1 = rsp + 88;
                sub_1400682A0(a1, v2, ptr);
                v1 = v_58;
                if (v1 != 3) JUMPOUT(0x14006811e);
                v8 = ptr->field_18;
                do {
                    v3 = ptr->field_10;
                    sub_1400682A0(str, v2, ptr);
                    v1 = (__int64)str;
                    if (v1 != 3) JUMPOUT(0x1400681e4);
                    v1 = ptr->field_18;
                    v8 = v1;
                } while ((v1 != v8));
                return sub_1400680A8();
            } else {
                if (v6 != 1) {
                    return sub_1400680A3();
                }
            }
        }
        v2 = ((__int64 *)a2)[2];
        v2 += 24;
        v5 = ptr->field_18;
        do {
            sub_1400682A0(str, v2, ptr);
            v1 = (__int64)str;
            if (v1 != 3) JUMPOUT(0x140068109);
            v1 = ptr->field_18;
            if (v1 == v5) JUMPOUT(0x1400680a8);
            v5 = v1;
            --v8;
        } while ((v8 != 0));
    }
    *dst = 3;
    return sub_14006828C();
}