from rfid import Pcsc, APDU
from smartcard.util import toHexString, toASCIIString, toASCIIBytes

def brute_instrs(tag):
    instrs = []
    for i in [0x0, 0x80]:
        for j in range(0x100):
            resp = tag.send(APDU(i, j))
            if resp != [0x6d, 0]:
                instrs.append([i, j])

    print 'Valid instructions: %s' % ', '.join(map(toHexString, instrs))
    # For my Visa Debit Paywave
    # Nothing selected: 00 70, 00 A4, 00 CA, 80 24, 80 50, 80 82, 80 CA, 80 D8, 80 E2, 80 E4, 80 E6, 80 E8, 80 F0, 80 F2
    # 1PAY.SYS.DDF01: 00 70, 00 A4, 00 B2
    # 2PAY.SYS.DDF01: 00 70, 00 A4, 00 B2
    # LINK/VISADEBIT: 00 20, 00 70, 00 82, 00 84, 00 88, 00 A4, 00 B2, 80 A8, 80 AE, 80 CA

with Pcsc.reader() as reader:
    for tag in reader.pn532.scan():
        brute_instrs(tag)

        print 'Selecting 2PAY'
        name, sfi, pdol = tag.emv.select_by_df(toASCIIBytes('2PAY.SYS.DDF01'))
        brute_instrs(tag)

        print 'Selecting 1PAY'
        name, sfi, pdol = tag.emv.select_by_df(toASCIIBytes('1PAY.SYS.DDF01'))
        brute_instrs(tag)

        data = tag.emv.read_record_parsed(0x1, sfi)
        apps = data.getlistparsed('APP')

        for priority, name, aid in apps:
            print 'Selecting %s' % name
            name, sfi, pdol_req = tag.emv.select_by_df(aid)
            brute_instrs(tag)

            if pdol_req:
                print 'Getting options'
                options = tag.emv.get_options(pdol_req)
                brute_instrs(tag)


