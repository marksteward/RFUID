"""
https://www.level2kernel.com/emv-glossary.html
The terminal may attempt to obtain a directory listing of all card applications from the card's PSE. If this is not supported or fails to find a match, the terminal must iterate through its AID list asking the card whether it supports each individual AID.
"""

"""
https://www.level2kernel.com/emv-glossary.html
The PPSE on a contactless card contains the list of all card applications supported by the contactless interface, and is returned from the card in response to the reader issuing a SELECT command for the PPSE.
"""


with Pcsc.reader() as reader:
	for tag in reader.pn532.scan():

		#print tag.find_unique_id()
		#continue


		emv = tag.emv
		# print map(hex, tag.find_14443_instrs())
		# 70, a4, ca

		def find_minimum_length(emv):
			# Some cards require a minimum filename length for selecting filenames
			name = '1PAY.SYS.DDF01'
			for i in range(len(name), 0, -1):
				try:
					prefix = name[:i]
					name, sfi = emv.select_by_df(toASCIIBytes(prefix))
				except Exception, e:
					if (e.sw1, e.sw2) == (0x6a, 0x82): # not found
						return i + 1

			return 0

		def select_all_by_df_no_next(emv, name):
			# You can't get the "next" filename when selecting by AID
			try:
				dfs = [emv.select_by_df(name)]
			except Exception, e:
				if not (e.sw1, e.sw2) == (0x6a, 0x82): # not found
					raise
				return []

			last_name, last_sfi = dfs[-1]
			curr = toASCIIBytes(last_name)
			while True:
				# curr will be a filled-out AID. Work our way back
				# to name until we've tried all this might have masked
				for i in reversed(range(len(name), len(curr))):
					curr[i] = (curr[i] + 1) % 256
					if curr[i] != 0:
						break
					del curr[i]
				else:
					return dfs

				try:
					dfs.append(emv.select_by_df(curr))
				except Exception, e:
					pass # FIXME


		apps = [
			toASCIIBytes('1PAY.SYS.DDF01'),  # EMV
			[0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],  # Visa
			[0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10],  # Visa Electron
			[0xa0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02],  # Visa CAP
			[0xa0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60],  # Maestro
			[0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],  # MasterCard
			[0xa0, 0x00, 0x00, 0x00, 0x04, 0x80, 0x02],  # MasterCard CAP
		]

		for app in apps:
			try:
				name, sfi = emv.select_by_df(app)
			except EMVException as e:
				print e.sw1, e.sw2
				if (e.sw1, e.sw2) != (0x6a, 0x82):
					raise
			else:
				print '%s: %s (%s)' % (app, name, sfi)

