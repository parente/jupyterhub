"""An example service authenticating with the Hub.

This serves `/services/whoami/`, authenticated with the Hub, showing the user their own info.
"""
import dateutil.parser
import os
import psutil
import re
import requests
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader

from tornado import gen
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.platform.asyncio import to_tornado_future
from tornado.web import RequestHandler, Application, authenticated

from jupyterhub.services.auth import HubAuthenticated
from jupyterhub._data import DATA_FILES_PATH
from jupyterhub.utils import url_path_join


KernelProcess = namedtuple('KernelProcess', 'pid user mem_percent mem_rss_gb kernel_id')
KernelState = namedtuple('KernelState', 'kernel_proc last_active_time state notebook')

HERE = os.path.abspath(os.path.dirname(__file__))
KERNEL_REGEX = re.compile(r'kernel-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).json')
GB = 1024 ** 3
cookie_jars = {}


def get_kernel_id(proc):
    for cmdline in (proc.cmdline(), proc.parent().cmdline()):
        m = KERNEL_REGEX.search(' '.join(cmdline))
        if m:
            return m.group(1)
    return None


def get_kernel_procs():
    kernel_procs = []
    for proc in psutil.process_iter():
        try:
            kernel_id = get_kernel_id(proc)
            if kernel_id is not None:
                kp = KernelProcess(proc.pid,
                                   proc.username(),
                                   proc.memory_percent(),
                                   proc.memory_info().rss / GB,
                                   kernel_id)
                kernel_procs.append(kp)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return kernel_procs


def get_user_cookies(hub_api, hub_headers, users, cookie_jars):
    for user in users:
        if user not in cookie_jars:
            resp = requests.post(url_path_join(hub_api, '/users/{}/admin-access'.format(user)),
                                 headers=hub_headers)
            if resp.ok:
                cookie_jars[user] = resp.cookies
    return cookie_jars


def get_user_servers(hub_api, hub_headers):
    resp = requests.get(url_path_join(hub_api, 'proxy'), headers=hub_headers)
    resp.raise_for_status()
    return resp.json()


def get_sessions(users, cookie_jars, user_servers):
    sessions = {}
    for user in users:
        host = user_servers['/user/'+user]['target']
        resp = requests.get(url_path_join(host, 'user', user, 'api/sessions'),
                            cookies=cookie_jars[user])
        if resp.ok:
            sessions[user] = resp.json()
    return sessions


def enrich_kernel_procs(kernel_procs, sessions):
    kernel_states = []
    for kp in kernel_procs:
        if kp.user not in sessions:
            continue
        for session in sessions[kp.user]:
            kernel = session.get('kernel', {})
            if kernel.get('id') == kp.kernel_id:
                ks = KernelState(kp,
                                 dateutil.parser.parse(kernel.get('last_activity', '')),
                                 kernel.get('execution_state'),
                                 os.path.basename(session.get('notebook', {}).get('path', '')))
                kernel_states.append(ks)
    return kernel_states


def get_kernel_resources(hub_api, hub_headers):
    global cookie_jars
    kernel_procs = get_kernel_procs()
    users = {kp.user for kp in kernel_procs}
    print(users)
    cookie_jars = get_user_cookies(hub_api, hub_headers, users, cookie_jars)
    print(cookie_jars)
    user_servers = get_user_servers(hub_api, hub_headers)
    print(user_servers)
    sessions = get_sessions(users, cookie_jars, user_servers)
    print(sessions)
    kernel_states = enrich_kernel_procs(kernel_procs, sessions)
    return kernel_states


async def update_loop(interval, hub_api, hub_headers):
    thread_pool = ThreadPoolExecutor(1)
    while True:
        future = thread_pool.submit(get_kernel_resources, hub_api, hub_headers)
        kernel_procs = await to_tornado_future(future)
        print('kernel_specs', kernel_procs)
        await gen.sleep(interval)


class ResourceDashboard(HubAuthenticated, RequestHandler):
    @authenticated
    def get(self):
        user = self.get_current_user()
        self.set_header('content-type', 'text/html')
        tmpl = self.settings['jinja2_env'].get_template('dashboard.html')
        ns = dict(
            user=user,
            static_url=self.static_url,
            logout_url=self.settings['logout_url'],
            base_url=self.settings['base_url']
        )
        self.finish(tmpl.render(**ns))
        # self.write(json.dumps(user_model, indent=1, sort_keys=True))


def main():
    base_url = os.environ['JUPYTERHUB_BASE_URL']
    service_prefix = os.environ['JUPYTERHUB_SERVICE_PREFIX']
    template_paths = [os.path.join(DATA_FILES_PATH, 'templates'),
                      os.path.join(HERE, 'templates')]
    settings = dict(
        base_url=base_url,
        login_url=url_path_join(base_url, 'hub/login'),
        logout_url=url_path_join(base_url, 'hub/logout'),
        static_path=os.path.join(DATA_FILES_PATH, 'static'),
        static_url_prefix=url_path_join(service_prefix, 'static/'),
        jinja2_env=Environment(
            loader=FileSystemLoader(template_paths)
        )
    )
    app = Application([
        (service_prefix + '/?', ResourceDashboard),
    ], **settings)

    http_server = HTTPServer(app)
    url = urlparse(os.environ['JUPYTERHUB_SERVICE_URL'])
    http_server.listen(url.port, url.hostname)

    hub_api = os.environ['JUPYTERHUB_API_URL']
    hub_headers = {'Authorization': 'token ' + os.environ['JUPYTERHUB_API_TOKEN']}
    IOLoop.current().spawn_callback(update_loop, 10, hub_api, hub_headers)
    IOLoop.current().start()


if __name__ == '__main__':
    main()
