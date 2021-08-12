#! /usr/bin/env python3

import sys
import base64


def main():
	if len(sys.argv) < 3:
		print("Usage: {} <obfuscated_script_path> <deobfuscated_script_output_path>".format(sys.argv[0]))
		return
	with open(sys.argv[1], 'r') as obf_script:
		obf_data = obf_script.read()
	orig_array = obf_data[obf_data.find('[')+1: obf_data.find(']')]
	orig_array = orig_array.replace("'", "").split(',')
	array_var_name = obf_data[obf_data.find('var ')+4: obf_data.find('=')].strip()
	shift_call_plc = obf_data.find(array_var_name+',',  obf_data.find(']'))
	shift_call_plc += len(array_var_name)
	shift_num = int(obf_data[obf_data.find('0x', shift_call_plc)+2:obf_data.find(')', obf_data.find('0x', shift_call_plc)+2)], 16)
	shift_num %= len(orig_array)
	shift_array = orig_array[shift_num:] + orig_array[:shift_num]
	str_access_var_name = obf_data[obf_data.find('var ', shift_call_plc)+4:obf_data.find('=',shift_call_plc)].strip()
	print(repr(str_access_var_name))
	deobf_data = obf_data[:]
	try:
		b = base64.b64decode(shift_array[0])
		b = base64.b64decode(shift_array[1])
		b = base64.b64decode(shift_array[2])
		b64 = True
	except:
		b64 = False
	for counter in range(len(shift_array)):
		if b64:
			dec_str = base64.b64decode(shift_array[counter]).decode('utf-8')
		else:
			dec_str = shift_array[counter]
		deobf_data = deobf_data.replace("{}('0x{}')".format(str_access_var_name,\
		 hex(counter)[2:]), repr(dec_str))
	with open(sys.argv[2], 'w') as deob_script:
		deob_script.write(deobf_data)
	print("Finished!")


if __name__ == '__main__':
	main()
