__int64 sub_140018B70();
__int64 sub_140018820();
extern __int64 off_140118695;
extern __int64 off_14008F3D0;
extern __int64 off_140118698;
extern __int64 off_14008F3A0;
extern __int64 off_14011869B;
extern __int64 off_1401109E4;
extern __int64 off_140110A3D;
extern __int64 off_1401186A2;
extern __int64 off_1401186A0;
extern __int64 off_14010B402;
extern __int64 off_14011F064;
extern __int64 off_14010B400;
extern __int64 off_1401163F2;
extern __int64 off_1401109F8;
extern __int64 off_14011F044;

__int64 __fastcall sub_14008F160(int *a1, int *a2) {
    __int64 rsp;
    int arg_12;
    int arg_18;
    int arg_8;
    __int64 v_20;
    __int64 v_38;
    __int64 v_40;
    int v_41;
    __int64 v_48;
    int *v_0;
    char *str;
    __int64 *src;
    __int64 *result;
    __int64 v3;
    __int64 *v6;
    int v5;
    __int64 v7;
    __int64 *src2;
    __int64 *src3;
    __int64 *src4;
    __int64 v2;

    src = (__int64 *)a2;
    result = *a1;
    if (result == 0) {
        v3 = a1 + 4;
        ++a1;
        str = (char *)a1;
        a1 = *src;
        v6 = (__int64 *)arg_8;
        a2 = &off_140118695;
        v5 = 3;
        ((__int64 (*)())(*(v6 + 24)))();
        v_38 = (__int64)src;
        v_40 = (__int64)result;
        v_41 = 0;
        v7 = &off_14008F3D0;
        v_20 = v7;
        a2 = &off_140118698;
        src = rsp + 56;
        sub_140018B70(src, a2, 3, v3);
        result = &off_14008F3A0;
        v_20 = (__int64)result;
        a2 = &off_14011869B;
        sub_140018B70(src, a2, 5, str);
        a1 = (int *)v_40;
        result = (__int64 *)v_41;
        a2 = (int *)result;
        a2 = (int *)(~(__int64)a2);
        a2 = (int *)((__int64)(__int64)a2 | (__int64)a1);
        if (((__int64)a2 & 1) == 0) {
            result = (__int64 *)v_38;
            if ((arg_12 & 128) != 0) {
                a1 = *result;
                result = (__int64 *)arg_8;
                a2 = &off_1401109E4;
                v5 = 1;
                ((__int64 (*)())(arg_18))();
            } else {
                a1 = *result;
                result = (__int64 *)arg_8;
                a2 = &off_140110A3D;
                v5 = 2;
                ((__int64 (*)())(arg_18))();
            }
        } else {
            result = (__int64 *)((__int64)(__int64)result | (__int64)a1);
        }
        result = (__int64 *)((__int64)(__int64)result & 1);
        return (__int64)result;
    } else {
        if (result != 1) {
            a1 = *src;
            src2 = (__int64 *)arg_8;
            src2 = *(src2 + 24);
            a2 = &off_1401186A2;
            v5 = 11;
            JUMPOUT(src2);
            return v5;
        } else {
            src3 = (__int64 *)a1;
            v3 = *src;
            src4 = (__int64 *)arg_8;
            v2 = *(src4 + 24);
            a2 = &off_1401186A0;
            ((__int64 (*)())v2)(v3, a2, 2);
            a1 = (int *)result;
            result = 1;
            if (a1 == 0) {
                if ((arg_12 & 128) != 0) {
                    a2 = &off_14010B402;
                    ((__int64 (*)())v2)(v3, a2, 2);
                    if (result == 0) {
                        str = 1;
                        v_38 = v3;
                        v_40 = (__int64)src4;
                        result = rsp + 48;
                        v_48 = (__int64)result;
                        result = *(src3 + 1);
                        a1 = &off_14011F064;
                        a2 = v_0[(__int64)result];
                        a2 = (int *)((__int64)a2 + (__int64)a1);
                        a1 = rsp + 56;
                        sub_140018820(a1, a2, 3);
                        if (result == 0) {
                            a2 = &off_14010B400;
                            a1 = rsp + 56;
                            sub_140018820(a1, a2, 2);
                            result = 1;
                            if (!((result != 0))) {
                                a2 = &off_1401163F2;
                                ((__int64 (*)())v2)(v3, a2, 1);
                            }
                        } else {
                            result = 1;
                        }
                        return (__int64)result;
                    }
                } else {
                    a2 = &off_1401109F8;
                    ((__int64 (*)())v2)(v3, a2, 1);
                    if (result != 0) {
                        return (__int64)a2;
                    } else {
                        result = *(src3 + 1);
                        a1 = &off_14011F044;
                        a2 = v_0[(__int64)result];
                        a2 = (int *)((__int64)a2 + (__int64)a1);
                        ((__int64 (*)())v2)(v3, a2, 3);
                        result = 1;
                        if (!((result != 0))) {
                            return (__int64)result;
                        }
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            }
        }
        return (__int64)result;
    }
    return (__int64)result;
}