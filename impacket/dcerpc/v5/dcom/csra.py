# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-CSRA]: 
#
from __future__ import division
from __future__ import print_function

import struct

from impacket.dcerpc.v5.ndr import NDRENUM, NDRSTRUCT, NDRUniConformantArray
from impacket.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown
from impacket.dcerpc.v5.dtypes import DWORD, DWORD_ARRAY, LONG, ULONG, LPWSTR, NULL, LPBYTE
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors
from impacket.uuid import string_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'CSRA SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'CSRA SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################
# 1.9 Standards Assignments
CLSID_CSRA = string_to_bin('d99e6e73-fc88-11d0-b498-00a0c90312f3')

#IID_ICertAdminD = uuidtup_to_bin(('d99e6e71-fc88-11d0-b498-00a0c90312f3', '0.0'))
IID_ICertAdminD = string_to_bin('d99e6e71-fc88-11d0-b498-00a0c90312f3')

#IID_ICertAdminD2 = uuidtup_to_bin(('7fe0d935-dda6-443f-85d0-1cfb58fe41dd', '0.0'))
IID_ICertAdminD2 = string_to_bin('7fe0d935-dda6-443f-85d0-1cfb58fe41dd')

ERROR_ARITHMETIC_OVERFLOW = 0x1

error_status_t = LONG

class TableType(NDRENUM):
    class enumItems(Enum):
        Request = 0x0000
        Extension = 0x3000
        Attribute = 0x4000
        CRL = 0x5000

class ColumnType(NDRENUM):
    class enumItems(Enum):
        Integer = 0x01
        Date = 0x02
        Bytes = 0x03
        String = 0x04


# 2.2.1.3 CERTVIEWRESTRICTION SeekOperator
class SeekOperator(NDRENUM):
    class enumItems(Enum):
        SeekOperator_EQ = 0x01
        SeekOperator_LT = 0x02
        SeekOperator_LE = 0x04
        SeekOperator_GE = 0x08
        SeekOperator_GT = 0x10

# 2.2.1.3 CERTVIEWRESTRICTION SortOrder
class SortOrder(NDRENUM):
    class enumItems(Enum):
        SortOrder_NONE = 0x00
        SortOrder_ASC = 0x01
        SortOrder_DSC = 0x02

# 2.2.1.3 CERTVIEWRESTRICTION
class CERTVIEWRESTRICTION(NDRSTRUCT):
    structure = (
        ('ColumnIndex', DWORD),
        ('SeekOperator', LONG),
        ('SortOrder', LONG),
        ('pbValue', LPBYTE),
        ('cbValue', DWORD),
    )

class CERTVIEWRESTRICTION_ARRAY(NDRUniConformantArray):
    item = CERTVIEWRESTRICTION


# 2.2.1.4 CERTTRANSBLOB
class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ('cb', ULONG),
        ('pb', LPBYTE),
    )


# 2.2.1.7 CERTTRANSDBCOLUMN
class CERTTRANSDBCOLUMN(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Index', DWORD),
        ('cbMax', DWORD),
        ('obwszName', ULONG),
        ('obwszDisplayName', ULONG),
    )


# 2.2.1.10 CERTTRANSDBRESULTCOLUMN
class CERTTRANSDBRESULTCOLUMN(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Index', DWORD),
        ('obValue', ULONG),
        ('cbValue', DWORD),
    )


# 2.2.3 CERTTRANSDBRESULTROW
class CERTTRANSDBRESULTROW(NDRSTRUCT):
    structure = (
        ('rowid', DWORD),
        ('ccol', DWORD),
        ('cbrow', ULONG),
    )



# 3.1.4.1.9 ICertAdminD::EnumViewColumn (Opnum 11)
class ICertAdminD_EnumViewColumn(DCOMCALL):
    opnum = 11
    structure = (
        ('pwszAuthority', LPWSTR),
        ('iColumn', DWORD),
        ('cColumn', DWORD),
    )

class ICertAdminD_EnumViewColumnResponse(DCOMANSWER):
    structure = (
        ('pcColumn', DWORD),
        ('pctbColumnInfo', CERTTRANSBLOB),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.1.12 ICertAdminD::OpenView (Opnum 14)
class ICertAdminD_OpenView(DCOMCALL):
    opnum = 14
    structure = (
        ('pwszAuthority', LPWSTR),
        ('ccvr', DWORD),
        ('acvr', CERTVIEWRESTRICTION_ARRAY),
        ('ccolOut', DWORD),
        ('acolOut', DWORD_ARRAY),
        ('ielt', DWORD),
        ('celt', DWORD),
    )

class ICertAdminD_OpenViewResponse(DCOMANSWER):
    structure = (
        ('pceltFetched', DWORD),
        ('pctbResultRows', CERTTRANSBLOB),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.1.13 ICertAdminD::EnumView (Opnum 15)
class ICertAdminD_EnumView(DCOMCALL):
    opnum = 15
    structure = (
        ('pwszAuthority', LPWSTR),
        ('ielt', DWORD),
        ('celt', DWORD),
    )

class ICertAdminD_EnumViewResponse(DCOMANSWER):
    structure = (
        ('pceltFetched', DWORD),
        ('pctbResultRows', CERTTRANSBLOB),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.1.14 ICertAdminD::CloseView (Opnum 16)
class ICertAdminD_CloseView(DCOMCALL):
    opnum = 16
    structure = (
        ('pwszAuthority', LPWSTR),
    )

class ICertAdminD_CloseViewResponse(DCOMANSWER):
    structure = (
        ('ErrorCode', error_status_t),
    )


#UNTESTED
# 3.1.4.1.16 ICertAdminD::Ping (Opnum 18)
#class ICertAdminD_Ping(DCOMCALL):
#    opnum = 18
#    structure = (
#        ('pwszAuthority', LPWSTR),
#    )
#
#class ICertAdminD_PingResponse(DCOMANSWER):
#    structure = (
#        ('ErrorCode', error_status_t),
#    )


# 3.1.4.1.17 ICertAdminD::GetServerState (Opnum 19)
class ICertAdminD_GetServerState(DCOMCALL):
    opnum = 19
    structure = (
        ('pwszAuthority', LPWSTR),
    )

class ICertAdminD_GetServerStateResponse(DCOMANSWER):
    structure = (
        ('pdwState', DWORD),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.2.4 ICertAdminD2::GetCAPropertyInfo (Opnum 34)
class ICertAdminD2_GetCAPropertyInfo(DCOMCALL):
    opnum = 34
    structure = (
        ('pwszAuthority', LPWSTR),
    )

class ICertAdminD2_GetCAPropertyInfoResponse(DCOMANSWER):
    structure = (
        ('pcProperty', LONG),
        ('pctbPropInfo', CERTTRANSBLOB),
        ('ErrorCode', error_status_t),
    )


# 3.1.4.2.5 ICertAdminD2::EnumViewColumnTable
class ICertAdminD2_EnumViewColumnTable(DCOMCALL):
    opnum = 35
    structure = (
        ('pwszAuthority', LPWSTR),
        ('iTable', DWORD),
        ('iColumn', DWORD),
        ('cColumn', DWORD),
    )

class ICertAdminD2_EnumViewColumnTableResponse(DCOMANSWER):
    structure = (
        ('pcColumn', DWORD),
        ('pctbColumnInfo', CERTTRANSBLOB),
        ('ErrorCode', error_status_t),
    )


#UNTESTED
## 3.1.4.2.8 ICertAdminD2::Ping2 (Opnum 38)
#class ICertAdminD2_Ping2(DCOMCALL):
#    opnum = 38
#    structure = (
#        ('pwszAuthority', LPWSTR),
#    )
#
#class ICertAdminD2_Ping2Response(DCOMANSWER):
#    structure = (
#        ('ErrorCode', error_status_t),
#    )




# helper functions
def find_null_term_utf_16le(seq):
    result = ''
    for pos in range(0, len(seq), 2):
        chunk = seq[pos:pos+2]
        if chunk == b'\0\0':
            break
        result += chunk.decode('utf-16le')
    return result


def parse_GetCAPropertyInfo_result(res):
    results = []

    num_properties = res['pcProperty']
    properties_blob = b''.join(res['pctbPropInfo']['pb'])

    # see MS-WCCE 2.2.2.3

    # typedef struct _CATRANSPOP {
    #  LONG lPropID;
    #  BYTE propType;
    #  BYTE Reserved;
    #  USHORT propFlags;
    #  ULONG obwszDisplayName;
    # } CATRANSPOP;

    n = 0
    i = 0
    while n < num_properties:
        prop_record_fmt = "<lBBHI"
        prop_record_size = struct.calcsize(prop_record_fmt)

        (iPropID, propType, Reserved, propFlags, obwszDisplayName) = \
                struct.unpack(prop_record_fmt, properties_blob[i:i+prop_record_size])

        tmp = properties_blob[obwszDisplayName:]
        propName = find_null_term_utf_16le(tmp)

        i += prop_record_size
        n += 1
        results.append((iPropID, propType, propFlags, propName))

    return results


def parse_EnumViewColumn_result(res):
    results = []

    num_columns = res['pcColumn']
    columns_blob = b''.join(res['pctbColumnInfo']['pb'])

    # see MS-CSRA 2.2.1.7.1

    # typedef struct _CERTTRANSDBCOLUMN {
    #  DWORD Type;
    #  DWORD Index;
    #  DWORD cbMax;
    #  ULONG obwszName;
    #  ULONG obwszDisplayName;
    # } CERTTRANSDBCOLUMN;

    n = 0
    i = 0
    while n < num_columns:
        col_record_fmt = "<IIILL"
        col_record_size = struct.calcsize(col_record_fmt)

        (combined_Type, Index, cbMax, obwszName, obwszDisplayName) = \
                struct.unpack(col_record_fmt, columns_blob[i:i+col_record_size])

        Flags = (combined_Type >> 16) & 0xffff
        Type = combined_Type & 0xffff

        tmp = columns_blob[obwszName:]
        columnName = find_null_term_utf_16le(tmp)

        tmp = columns_blob[obwszDisplayName:]
        columnDisplayName = find_null_term_utf_16le(tmp)

        i += col_record_size
        n += 1

        results.append((Index, Type, Flags, cbMax, columnName, columnDisplayName))

    return results


def parse_resultrows(num_resultrows, resultrows_blob, callback):
    # see MS-CSRA 2.2.3
    #
    #typedef struct _CERTTRANSDBRESULTROW {
    # DWORD rowid;
    # DWORD ccol;
    # ULONG cbrow;
    #} CERTTRANSDBRESULTROW;
    row_record_fmt = "<IIL"
    row_record_size = struct.calcsize(row_record_fmt)

    # see MS-CSRA 2.2.1.10
    #
    #typedef struct _CERTTRANSDBRESULTCOLUMN {
    # DWORD Type;
    # DWORD Index;
    # ULONG obValue;
    # DWORD cbValue;
    #} CERTTRANSDBRESULTCOLUMN;
    col_record_fmt = "<IILI"
    col_record_size = struct.calcsize(col_record_fmt)

    rowid = None

    n = 0
    i = 0
    while n < num_resultrows:
        row = []

        (rowid, ccol, cbrow) = struct.unpack(row_record_fmt, resultrows_blob[i:i+row_record_size])

        ii = i + row_record_size

        m = 0
        while m < ccol:
            (combined_Type, Index, obValue, cbValue) = struct.unpack(col_record_fmt, resultrows_blob[ii:ii+col_record_size])

            Flags = (combined_Type >> 16) & 0xffff
            Type = combined_Type & 0xffff

            Value = resultrows_blob[i+obValue:i+obValue+cbValue]

            if Type == ColumnType.Integer:
                Value = int.from_bytes(Value, 'little', signed=True)
            elif Type == ColumnType.Date:
                #TODO: how to parse the 8-byte date data?
                pass
            elif Type == ColumnType.Bytes:
                pass
            elif Type == ColumnType.String:
                Value = Value.decode('utf-16le')
                #remove NULL termination
                if Value.endswith('\0'):
                    Value = Value[:-1]

            row.append((Index, Type, Flags, Value))

            ii += col_record_size
            m += 1

        callback(rowid, row)

        i += cbrow
        n += 1

    # NOTE: There does not appear to be an empty CERTTRANSDBRESULTROW appended
    #       at the end of enumeration as specified in 3.1.4.1.13 .
    #
    #       So there does not appear to be a way to determine the end of enumeration
    #       without trying values of ielt that cause a 0x1 error.

    # return the rowid of the last handled resultrow
    return rowid

def parse_OpenView_result(res, callback):
    num_resultrows = res['pceltFetched']
    resultrows_blob = b''.join(res['pctbResultRows']['pb'])

    return parse_resultrows(num_resultrows, resultrows_blob, callback)

def parse_EnumView_result(res, callback):
    return parse_OpenView_result(res, callback)


def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string




class ICertAdminDObject(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertAdminD

    def GetServerState(self, pwszAuthority):
        request = ICertAdminD_GetServerState()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def OpenView(self, pwszAuthority, ccvr, acvr, ccolOut, acolOut, ielt, celt):
        request = ICertAdminD_OpenView()

        request['pwszAuthority'] = checkNullString(pwszAuthority)
        request['ccvr'] = ccvr
        request['acvr'] = acvr
        request['ccolOut'] = ccolOut
        request['acolOut'] = acolOut
        request['ielt'] = ielt
        request['celt'] = celt
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def hl_OpenView(self, callback, pwszAuthority, restrictions=None, columns=None, celt=1):
        if restrictions is None:
            restrictions = []

        if columns is None or len(columns) == 0:
            raise Exception("columns must not be empty")

        res = self.OpenView(pwszAuthority,
                            len(restrictions), restrictions,
                            len(columns), columns,
                            1,   # values other than one yield unexpected results
                            0)   # do not accept any results with this call;
                                 # instead use EnumView below
        ielt = 1
        while True:
            try:
                res = self.EnumView(pwszAuthority,
                                    ielt,
                                    celt) # must be <= the number of results returned, otherwise
                                          # it will raise impacket.dcerpc.v5.dcom.csra.DCERPCSessionError: SCMP SessionError: unknown error code: 0x1
                                          # ; hence celt is dropped to one upon exception below

                ielt = parse_EnumView_result(res, callback)

                if ielt is None:
                    break

                ielt += 1

            except DCERPCSessionError as e:
                if e.error_code == ERROR_ARITHMETIC_OVERFLOW:
                    if celt == 1:
                        # ielt is out of range, take this as a sign of end-of-enumeration
                        break
                    else:
                        # try again with one record at a time
                        celt = 1
                    continue
                else:
                    raise

        self.CloseView(pwszAuthority)

    def EnumView(self, pwszAuthority, ielt, celt):
        request = ICertAdminD_EnumView()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        request['ielt'] = ielt
        request['celt'] = celt
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def CloseView(self, pwszAuthority):
        request = ICertAdminD_CloseView()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def EnumViewColumn(self, pwszAuthority, iColumn, cColumn):
        request = ICertAdminD_EnumViewColumn()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        request['iColumn'] = iColumn
        request['cColumn'] = cColumn
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def hl_EnumViewColumn(self, pwszAuthority):
        results = {}
        for (Index, Type, Flags, cbMax, columnName, columnDisplayName) in \
                parse_EnumViewColumn_result(self.EnumViewColumn(pwszAuthority, 0, 1000)):
            results[columnName] = (Index, Type, cbMax, columnDisplayName)
        return results

    #UNTESTED
    #def Ping(self, pwszAuthority):
    #    request = ICertAdminD_Ping()
    #    request['pwszAuthority'] = checkNullString(pwszAuthority)
    #    resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
    #    return resp



class ICertAdminD2Object(ICertAdminDObject):
    def __init__(self, interface):
        ICertAdminDObject.__init__(self, interface)
        self._iid = IID_ICertAdminD2

    def GetCAPropertyInfo(self, pwszAuthority):
        request = ICertAdminD2_GetCAPropertyInfo()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def EnumViewColumnTable(self, pwszAuthority, iTable, iColumn, cColumn):
        request = ICertAdminD2_EnumViewColumnTable()
        request['pwszAuthority'] = checkNullString(pwszAuthority)
        request['iTable'] = iTable
        request['iColumn'] = iColumn
        request['cColumn'] = cColumn
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

    def hl_EnumViewColumnTable(self, pwszAuthority, iTable):
        results = {}
        for (Index, Type, Flags, cbMax, columnName, columnDisplayName) in \
                parse_EnumViewColumn_result(self.EnumViewColumnTable(pwszAuthority, iTable, 0, 1000)):
            results[columnName] = (Index, Type, cbMax, columnDisplayName)
        return results

    #UNTESTED
    #def Ping2(self, pwszAuthority):
    #    request = ICertAdminD2_Ping2()
    #    request['pwszAuthority'] = checkNullString(pwszAuthority)
    #    resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
    #    return resp
