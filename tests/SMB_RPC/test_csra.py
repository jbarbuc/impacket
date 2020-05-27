###############################################################################
#  Tested so far: 
#

#  Not yet:
#
################################################################################

from __future__ import division
from __future__ import print_function
import unittest
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

import os

from impacket.dcerpc.v5 import dcomrt

from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS

from impacket.dcerpc.v5.dcom import csra

from impacket import LOG

import logging

LOG.setLevel(logging.DEBUG)
h_stream = logging.StreamHandler()
LOG.addHandler(h_stream)

class CSRATests(unittest.TestCase):
    def populateByPassword(self):
        userPrinc = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _, sessionKey = getKerberosTGT(userPrinc, self.password, self.domain, '', '', '')
        TGT = {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}

        name = 'RPCSS/%s' % self.servername
        serverName = Principal('RPCSS/%s' % self.servername,
                               type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = \
                getKerberosTGS(serverName, self.domain, None, TGT['KDC_REP'],
                               TGT['cipher'], TGT['sessionKey'])

        TGS = {'KDC_REP': tgs, 'cipher': cipher, 'sessionKey': sessionKey}

        self.TGT = TGT
        self.TGS = TGS


    def test_openview(self):
        self.populateByPassword()

        dcom = dcomrt.DCOMConnection(self.servername,
                                     username=self.username,
                                     domain=self.domain,
                                     TGT=self.TGT,
                                     TGS=self.TGS,
                                     oxidResolver=False,
                                     doKerberos=True)

        iInterface = dcom.CoCreateInstanceEx(csra.CLSID_CSRA, csra.IID_ICertAdminD2)
        foo = csra.ICertAdminD2Object(iInterface)

        request_columns = foo.hl_EnumViewColumnTable(self.caCN, csra.TableType.Request)

        def get_index_by_name(column_name, column_type):
            if column_name in request_columns:
                (Index, Type, _, _) = request_columns[column_name]
                if Type == column_type:
                    return Index
                else:
                    raise Exception('unexpected column type: %d != %d' % (Type, column_type))
            else:
                raise Exception('non-existent column name: %s' % (column_name,))

        index_SerialNumber = get_index_by_name('SerialNumber', csra.ColumnType.String)

        #restriction = csra.CERTVIEWRESTRICTION()
        #restriction['ColumnIndex'] = index_SerialNumber
        #restriction['SeekOperator'] = csra.SeekOperator.SeekOperator_EQ   # for binary type, must be SeekOperator_EQ
        #restriction['SortOrder'] = csra.SortOrder.SortOrder_NONE
        #
        #serialNumber = 0xff000000000001
        #
        ## referenced as a hex-formatted string in utf-16le
        #serialNumberBytes = ("%x" % serialNumber).encode('utf-16le')
        #
        #serialNumberBytes_array = []
        #for _byte in serialNumberBytes:
        #    serialNumberBytes_array.append(bytes([_byte]))
        #restriction['pbValue'] = serialNumberBytes_array
        #restriction['cbValue'] = len(serialNumberBytes_array)
        #restrictions = [restriction]

        restrictions = []

        columns = [index_SerialNumber]

        def handleRow(rowid, row):
            for (Index, Type, Flags, Value) in row:
                if Type == csra.ColumnType.Integer:
                    LOG.debug("%d 0x%0x %d", rowid, Index, Value)
                elif Type == csra.ColumnType.Date:
                    LOG.debug("%d 0x%0x [date] %s", rowid, Index, Value)
                elif Type == csra.ColumnType.Bytes:
                    LOG.debug("%d 0x%0x len(%d) %s", rowid, Index, len(Value), Value)
                elif Type == csra.ColumnType.String:
                    LOG.debug("%d 0x%0x %s", rowid, Index, Value)

        foo.hl_OpenView(handleRow,
                        self.caCN,
                        restrictions=restrictions,
                        columns=columns,
                        celt=10)

        iInterface.RemRelease()

        foo.RemRelease()

        dcom.disconnect()


class TCPTransport(CSRATests):
    def setUp(self):
        CSRATests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.password = configFile.get('TCPTransport', 'password')
        self.domain = configFile.get('TCPTransport', 'domain')
        self.servername = configFile.get('TCPTransport', 'servername')
        self.caCN = configFile.get('TCPTransport', 'CSRA_caCN')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)
