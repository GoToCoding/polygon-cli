import hashlib
import json
import random
import sys
import time
from getpass import getpass

from xml.etree import ElementTree
import os
import glob
import requests

from . import config
from . import polygon_file
from . import utils
from .exceptions import PolygonNotLoginnedError, ProblemNotFoundError, PolygonApiError
from .polygon_html_parsers import *


def get_login_password():
    if config.login:
        print('Using login %s from config' % config.login)
    else:
        print('Enter login:', end=' ')
        sys.stdout.flush()
        config.login = sys.stdin.readline().strip()
    if config.password:
        print('Using password from config')
    else:
        config.password = getpass('Enter password: ')


def parse_api_file_list(files, files_raw, type):
    for j in files_raw:
        file = polygon_file.PolygonFile()
        file.type = type
        file.name = j["name"]
        file.date = j["modificationTimeSeconds"]
        file.size = j["length"]
        files.append(file)


class ProblemSession:
    def __init__(self, address, problem_id):
        """

        :type address: str
        :type problem_id: int or None
        """
        self.polygon_address = address
        self.problem_id = problem_id
        self.owner = None
        self.problem_name = None
        self.session = requests.session()
        self.sessionId = None
        self.ccid = None
        self.local_files = []
        self.relogin_done = False

    def use_ready_session(self, data):
        """

        :type data: dict
        """
        cookies = data["cookies"]
        for i in cookies.keys():
            self.session.cookies.set(i, cookies[i])
        self.ccid = data["ccid"]
        assert self.problem_id == data["problemId"]
        self.sessionId = data["sessionId"]
        self.local_files = data["localFiles"]
        if "version" not in data:
            print('Your session file is too old, relogin required')
            self.sessionId = None
            self.ccid = None
        else:
            self.owner = data["owner"]
            self.problem_name = data["problemName"]

    def dump_session(self):
        """

        :rtype: dict
        :return: session ready to json-serialization
        """
        data = dict()
        data["problemId"] = self.problem_id
        data["sessionId"] = self.sessionId
        data["cookies"] = self.session.cookies.get_dict()
        data["ccid"] = self.ccid
        data["localFiles"] = self.local_files
        data["problemName"] = self.problem_name
        data["owner"] = self.owner
        data["version"] = 1
        return data

    def make_link(self, link, ccid=False, ssid=False):
        """

        :type link: str
        :type ccid: bool
        :type ssid: bool
        :rtype: str
        """
        if ccid:
            if link.find('?') != -1:
                link += '&'
            else:
                link += '?'
            if self.ccid is None:
                self.renew_http_data()
            link += 'ccid=%s' % self.ccid
        if ssid:
            if link.find('?') != -1:
                link += '&'
            else:
                link += '?'
            if self.sessionId is None:
                self.renew_http_data()
            link += 'session=%s' % self.sessionId
        if link.startswith('/'):
            result = self.polygon_address + link
        else:
            result = self.polygon_address + '/' + link
        return result

    def send_request(self, method, url, **kw):
        """

        :type method: str
        :type url: str
        :rtype: requests.Response
        :raises: PolygonNotLoginnedError
        """
        print('Sending request to ' + utils.prepare_url_print(url), end=' ')
        sys.stdout.flush()
        result = self.session.request(method, url, **kw)
        print(result.status_code)
        if result.url and result.url.startswith(config.polygon_url + '/login'):
            if not self.relogin_done:
                self.renew_http_data()
                return self.send_request(method, url, **kw)
            else:
                print('Already tried to relogin, but it didn''t helped')
                raise PolygonNotLoginnedError()
        return result

    def send_api_request(self, api_method, params, is_json=True, problem_data=True):
        print('Invoking ' + api_method, end=' ')
        sys.stdout.flush()
        params["apiKey"] = config.api_key
        params["time"] = int(time.time())
        if problem_data:
            params["problemId"] = self.problem_id
        signature_random = ''.join([chr(random.SystemRandom().randint(0, 25) + ord('a')) for _ in range(6)])
        signature_random = utils.convert_to_bytes(signature_random)
        for i in params:
            params[i] = utils.convert_to_bytes(params[i])
        param_list = [(utils.convert_to_bytes(key), params[key]) for key in params]
        param_list.sort()
        signature_string = signature_random + b'/' + utils.convert_to_bytes(api_method)
        signature_string += b'?' + b'&'.join([i[0] + b'=' + i[1] for i in param_list])
        signature_string += b'#' + utils.convert_to_bytes(config.api_secret)
        params["apiSig"] = signature_random + utils.convert_to_bytes(hashlib.sha512(signature_string).hexdigest())
        url = self.polygon_address + '/api/' + api_method
        result = self.session.request('POST', url, files=params)
        print(result.status_code)
        if not is_json and result.status_code == 200:
            return result.content
        result = json.loads(result.content.decode('utf8'))
        if result["status"] == "FAILED":
            print(result["comment"])
            raise PolygonApiError()
        if "result" in result:
            return result["result"]
        return None

    def get_script_content(self):
        for i in self.local_files:
            if i.type == 'script':
                return open(i.get_path(), 'rb').read()
        return None

    def login(self, login, password):
        """

        :type login: str
        :type password: str
        """
        fields = {
            "submitted": "true",
            "login": login,
            "password": password,
            "attachSessionToIp": "on",
            "submit": "Login",
        }

        url = self.make_link("login")
        result = self.send_request('POST', url, data=fields)
        parser = ExtractCCIDParser()
        parser.feed(result.text)
        assert parser.ccid
        self.ccid = parser.ccid

    def get_problem_links(self):
        """

        :rtype: dict
        """
        currentpage = 1
        while True:
            url = self.make_link('problems?page=%d' % currentpage, ccid=True)
            problems_page = self.send_request('GET', url).text
            parser = ProblemsPageParser(self.problem_id)
            parser.feed(problems_page)
            if parser.continueLink or parser.startLink:
                return {'continue': parser.continueLink,
                        'discard': parser.discardLink,
                        'start': parser.startLink,
                        'owner': parser.owner,
                        'problem_name': parser.problemName
                        }
            if currentpage >= parser.numberOfProblemPages:
                break
            currentpage += 1
        return {'continue': None,
                'discard': None,
                'start': None,
                'owner': None,
                'problem_name': None
                }

    def renew_http_data(self):
        self.relogin_done = True
        get_login_password()
        self.login(config.login, config.password)
        links = self.get_problem_links()
        if links['start'] is None and links['continue'] is None:
            raise ProblemNotFoundError()
        url = self.make_link(links['continue'] or links['start'])
        problem_page = self.send_request('GET', url).text
        parser = ExtractSessionParser()
        parser.feed(problem_page)
        self.sessionId = parser.session

    def get_solutions_list(self):
        """

        :rtype: list of polygon_file.PolygonFile
        """
        solutions_raw = self.send_api_request('problem.solutions', {})
        files = []
        parse_api_file_list(files, solutions_raw, 'solution')
        return files

    def get_files_list(self):
        """

        :rtype: list of polygon_file.PolygonFile
        """
        files_raw = self.send_api_request('problem.files', {})
        files = []
        types_map = {'sourceFiles': 'source', 'resourceFiles': 'resource', 'auxFiles': 'attachment'}
        for i in types_map:
            parse_api_file_list(files, files_raw[i], types_map[i])

        script = polygon_file.PolygonFile()
        script.type = 'script'
        script.name = 'script'
        files.append(script)
        return files

    def get_all_files_list(self):
        """

        :rtype: list of polygon_file.PolygonFile
        """
        return self.get_files_list() + self.get_solutions_list()

    def upload_file(self, name, type, content, is_new, tag=None, source_type=None):
        """
        Uploads new solution to polygon

        :type name: str
        :type type: str
        :type content: bytes
        :type is_new: bool
        :type tag: str or None
        :rtype: bool
        """
        options = {}
        if source_type is None:
            if name.endswith('.cpp'):
                options['sourceType'] = 'cpp.g++11'
            elif name.endswith('.java'):
                options['sourceType'] = 'java8'
        else:
            options['sourceType'] = source_type
        if is_new:
            options['checkExisting'] = 'true'
        else:
            options['checkExisting'] = 'false'
        options['name'] = name
        if type == 'solution':
            api_method = 'problem.saveSolution'
            if tag:
                options['tag'] = tag
        else:
            api_method = 'problem.saveFile'
            options['type'] = utils.get_api_file_type(type)
            if not options['type']:
                raise NotImplementedError("uploading file of type " + type)

        options['file'] = content
        try:
            self.send_api_request(api_method, options)
        except PolygonApiError as e:
            print(e)
            return False

        return True

    def set_utility_file(self, polygon_filename, type):
        """
        Sets checker or validator

        :type polygon_filename: str
        :type type: str
        """

        self.send_api_request('problem.set' + type.title(), {type: polygon_filename})

    def get_local_by_polygon(self, file):
        """

        :type file: polygon_file.PolygonFile
        :rtype: local_file.LocalFile or None
        """
        for local in self.local_files:
            if local.polygon_filename == file.name:
                return local
        return None

    def get_local_by_filename(self, filename):
        """

        :type filename: str
        :rtype: local_file.LocalFile or None
        """
        for local in self.local_files:
            if local.filename == filename:
                return local
        return None

    def download_test(self, test_num, test_directory='.'):
        """

        :type test_num: str
        """

        input = self.send_api_request('problem.testInput',
                                      {'testset': 'tests', 'testIndex': test_num},
                                      is_json=False)
        utils.safe_rewrite_file(test_directory + '/%03d' % int(test_num), utils.convert_newlines(input))
        answer = self.send_api_request('problem.testAnswer',
                                       {'testset': 'tests', 'testIndex': test_num},
                                       is_json=False)
        utils.safe_rewrite_file(test_directory + '/%03d.a' % int(test_num), utils.convert_newlines(answer))

    def download_all_tests(self):
        tests = self.send_api_request('problem.tests', {'testset': 'tests'})
        for t in tests:
            self.download_test(t["index"], config.subdirectory_paths['test'])

    def load_script(self):
        return self.send_api_request('problem.script', {'testset': 'tests'}, is_json=False)

    def update_groups(self, script_content):
        tests = self.get_tests()
        hand_tests = self.get_hand_tests_list(tests)
        groups = utils.parse_script_groups(script_content, hand_tests)
        test_group = {i["index"]: i["group"] if "group" in i else None for i in tests}
        if groups:
            for i in groups.keys():
                bad_current_groups = list(filter(lambda x: test_group[x] != i, groups[i]))
                if bad_current_groups:
                    print('Set group ' + str(i) + ' for tests ' + str(bad_current_groups))
                self.set_test_group(bad_current_groups, i)
        return True

    def upload_script(self, content):
        """
        Uploads script solution to polygon

        :type content: bytes
        """
        try:
            self.send_api_request('problem.saveScript', {'testset': 'tests', 'source': content})
        except PolygonApiError as e:
            print(e)
            return False
        return self.update_groups(content)

    def set_test_group(self, tests, group):
        for i in tests:
            self.send_api_request('problem.saveTest', {'testset': 'tests', 'testIndex': i, 'testGroup': group})

    def get_tests(self):
        return self.send_api_request('problem.tests', {'testset': 'tests'})

    def get_hand_tests_list(self, tests):
        result = []
        for i in tests:
            if i["manual"]:
                result.append(int(i["index"]))
        return result

    def get_contest_problems(self, contest_id):
        assert (self.problem_id is None)
        problems = self.send_api_request('contest.problems', {'contestId': contest_id}, problem_data=False)
        result = {}
        for i in problems.keys():
            result[problems[i]["name"]] = problems[i]["id"]
        return result

    def download_last_package(self):
        url = self.make_link('package', ssid=True, ccid=True)
        data = self.send_request('GET', url).text
        parser = PackageParser()
        parser.feed(data)
        print(parser.url)
        if parser.url is None:
            print('No package created')
            return
        link = self.make_link(parser.url, ssid=True, ccid=False)
        filename = parser.url
        filename = filename[:filename.find('.zip')]
        filename = filename[filename.rfind('/') + 1:]
        filename = filename[:filename.rfind('-')]
        f = open('%s.zip' % (filename), 'wb')
        r = self.send_request('GET', link)
        for c in r.iter_content(1024):
            if (c):
                f.write(c)
        f.close()

    def import_problem_from_package(self, directory):
        path_to_problemxml = os.path.join(directory, 'problem.xml')

        def upload_file_from_node(node, type, tag=None):
            if node.find('source') is not None:
                node = node.find('source')
            is_executable = type != 'resource' and type != 'attachment'
            filepath = os.path.join(directory, node.attrib['path'])
            source_type = node.attrib['type'] if is_executable else None
            f = open(filepath, 'rb')
            content = f.read()
            f.close()
            print('Adding ' + type + ': ' + filepath)
            return self.upload_file(os.path.basename(filepath), type, content, True, tag, source_type)

        if os.path.isfile(path_to_problemxml):
            problem_node = ElementTree.parse(path_to_problemxml)
        else:
            print("problem.xml not found or couldn't be opened")
            return
        if problem_node.find('tags') is not None:  # need API function to add tags
            print('tags:')
            for tag_node in problem_node.find('tags').findall('tag'):
                print(tag_node.attrib['value'])
        assets_node = problem_node.find('assets')
        for solution_node in assets_node.find('solutions').findall('solution'):
            xml_tag_to_api_tag = {'accepted': 'OK', 'main': 'MA', 'time-limit-exceeded': 'TL',
                                  'memory-limit-exceeded': 'ML', 'wrong-answer': 'WA',
                                  'incorrect': 'RJ', 'rejected' : 'RJ', 'time-limit-exceeded-or-accepted' : "TO"}
            upload_file_from_node(solution_node, 'solution', xml_tag_to_api_tag[solution_node.attrib['tag']])
        files_node = problem_node.find('files')
        if files_node is not None:
            resources_node = files_node.find('resources')
            if resources_node is not None:
                for resource_node in resources_node.findall('file'):
                    filepath = resource_node.attrib['path']
                    if filepath.endswith('testlib.h') or filepath.endswith('olymp.sty') or \
                            filepath.endswith('problem.tex') or filepath.endswith('statements.ftl'):
                        continue
                    upload_file_from_node(resource_node, 'resource')
            attachments_node = files_node.find('attachments')
            if attachments_node is not None:
                for attachment_node in attachments_node.findall('file'):
                    upload_file_from_node(attachment_node, 'attachment')
            executables_node = files_node.find('executables')
            if executables_node is not None:
                for executable_node in executables_node.findall('executable'):
                    upload_file_from_node(executable_node, 'source')
        for checker_node in assets_node.findall('checker'):
            if 'name' in checker_node.attrib and checker_node.attrib['name'].startswith('std::'):
                checker_name = checker_node.attrib['name']
            else:
                checker_name = checker_node.find('copy').attrib['path']
            self.set_utility_file(checker_name, 'checker')
        validators_node = assets_node.find('validators')
        if validators_node is not None:
            for validator_node in validators_node.findall('validator'):
                self.set_utility_file(os.path.basename(validator_node.find('source').attrib['path']), 'validator')
        for testset_node in problem_node.find('judging').findall('testset'):
            testset_name = testset_node.attrib['name']
            input_pattern = testset_node.find('input-path-pattern').text
            print('testset = ' + testset_name)
            test_id = 0
            script = ''
            tests_from_file = {}
            groups = {}
            for test_node in testset_node.find('tests').findall('test'):
                test_id += 1
                if 'group' in test_node.attrib:
                    group = test_node.attrib['group']
                    if group not in groups:
                        groups[group] = []
                    groups[group].append(str(test_id))
                if test_node.attrib['method'] == 'manual':
                    options = {}
                    options['checkExisting'] = 'true'
                    options['testset'] = testset_name
                    options['testIndex'] = str(test_id)
                    test_file = open(os.path.join(directory, input_pattern % test_id), 'r')
                    options['testInput'] = test_file.read()
                    test_file.close()
                    if 'sample' in test_node.attrib:
                        options['testUseInStatements'] = test_node.attrib['sample']
                    try:
                        print('Adding test %d' % test_id)
                        self.send_api_request('problem.saveTest', options)
                    except PolygonApiError as e:
                        print(e)
                else:
                    if 'from-file' in test_node.attrib:
                        cmd = test_node.attrib['cmd']
                        if not cmd in tests_from_file:
                            tests_from_file[cmd] = []
                        tests_from_file[cmd].append(int(test_node.attrib['from-file']))
                    else:
                        script_line = test_node.attrib['cmd'] + ' > $'  # (' > %d' % test_id)
                        script += script_line + '\n'
                        print('Added "' + script_line + '" to script')
            for cmd in tests_from_file:
                tests_list = tests_from_file[cmd]
                tests_list.sort()
                i = 0
                tests_str = ''
                while i < len(tests_list):
                    j = i + 1
                    while j < len(tests_list) and tests_list[j] - tests_list[i] == j - i:
                        j += 1
                    if len(tests_str) > 0:
                        tests_str += ','
                    tests_str += str(tests_list[i]) if i + 1 == j else '%d-%d' % (tests_list[i], tests_list[j - 1])
                    i = j
                script = ('%s > {%s}\n' % (cmd, tests_str)) + script
            if len(script) > 0:
                try:
                    self.send_api_request('problem.saveScript', {'testset': testset_name,
                                                                 'source': script})
                except PolygonApiError as e:
                    print(e)
            for group, tests in groups.items():
                print('Setting group %s for tests %s' % (group, str(tests)))
                self.set_test_group(tests, group)
            assert (test_id == int(testset_node.find('test-count').text))

    def import_problem_from_folder(self, directory):
        def get_files(masks):
            ret = []
            for f in masks:
                ret += glob.glob(os.path.join(directory, f))
            return ret
        def upload_file_from_path(path, type, tag=None):
            f = open(path, 'rb')
            content = f.read()
            f.close()
            print('Adding ' + type + ': ' + path)
            return self.upload_file(os.path.basename(path), type, content, True, tag)
        hsin_tests_added = 0
        for test_s in get_files(["*.dummy.in.*"]):
            test_id = int(test_s[test_s.rfind('.')+1:])
            options = {}
            options['checkExisting'] = 'true'
            options['testset'] = 'tests'
            options['testIndex'] = str(test_id)
            test_file = open(test_s, 'rb')
            hsin_tests_added += 1
            options['testInput'] = test_file.read()
            options['testDescription'] = 'polygon-cli import_problem, File %s' % test_s
            options['testUseInStatements'] = 'true'
            options['testGroup'] = '0'
            test_file.close()
            try:
                print('Adding %s hsin.hr sample test %d' % (test_s, test_id))
                self.send_api_request('problem.saveTest', options)
            except PolygonApiError as e:
                print(e)
        hsin_tests = {}
        hsin_groups_enabled = False
        for test_s in get_files(["*.in.*"]):
            if 'dummy' in test_s:
                continue
            test_id = test_s[test_s.rfind('.')+1:]
            while test_id[-1].isalpha():
                hsin_groups_enabled = True
                test_id = test_id[:-1]
            test_id = int(test_id)
            if test_id not in hsin_tests:
                hsin_tests[test_id] = []
            hsin_tests[test_id].append(test_s)
        hsin_tests = list((key, value) for (key, value) in hsin_tests.items())
        hsin_tests.sort(key=lambda x: x[0])
        for group, tests in hsin_tests:
            for test_s in tests:
                options = {}
                options['checkExisting'] = 'true'
                options['testset'] = 'tests'
                hsin_tests_added += 1
                options['testIndex'] = str(hsin_tests_added)
                test_file = open(test_s, 'rb')
                options['testInput'] = test_file.read()
                options['testDescription'] = 'polygon-cli, File %s' % test_s
                options['testGroup'] = str(group) if hsin_groups_enabled else '1'
                test_file.close()
                try:
                    print('Adding %s hsin.hr test %d from group %d' % (test_s, hsin_tests_added, group))
                    self.send_api_request('problem.saveTest', options)
                except PolygonApiError as e:
                    print(e)
        # hsin_main = list(filter(lambda x: 'dummy' not in x, get_files(["hsintests/*.in.*"])))
        atcoder_tests = 0
        for group in range(0, 100):
            for test_id in range(0, 100):
                for test_s in get_files(["tests/%d_%02d.txt" % (group, test_id)]):
                    options = {}
                    options['checkExisting'] = 'true'
                    options['testset'] = 'tests'
                    atcoder_tests += 1
                    options['testIndex'] = str(atcoder_tests)
                    test_file = open(test_s, 'rb')
                    options['testInput'] = test_file.read()
                    options['testDescription'] = 'polygon-cli, File %s' % test_s
                    options['testGroup'] = str(group)
                    if group == 0:
                        options['testUseInStatements'] = 'true'
                    test_file.close()
                    try:
                        print('Adding atcoder test %d from group %d' % (atcoder_tests, group))
                        self.send_api_request('problem.saveTest', options)
                    except PolygonApiError as e:
                        print(e)
        for test_s in get_files(["src/*.hand", "src/*.manual", "src/*.t", "src/*.sample"]):
            test_id = int(os.path.splitext(os.path.basename(test_s))[0])
            options = {}
            options['checkExisting'] = 'true'
            options['testset'] = 'tests'
            options['testIndex'] = str(test_id)
            test_file = open(test_s, 'rb')
            options['testInput'] = test_file.read()
            options['testDescription'] = 'polygon-cli import_problem, File %s' % test_s
            if test_s.endswith('.sample'):
                options['testUseInStatements'] = 'true'
            test_file.close()
            try:
                print('Adding test %d' % test_id)
                self.send_api_request('problem.saveTest', options)
            except PolygonApiError as e:
                print(e)
        for filepath in get_files(["solutions/*.cpp", "solutions/*.java", "solutions/*.pas", "solutions/*.dpr", \
                                    "solutions/*.py", "solutions/*.c++"]):
            upload_file_from_path(filepath, 'solution', 'RJ')
        for filepath in get_files(["src/*.h", "src/testlib.pas"]):
            if os.path.basename(filepath) in {'testlib.h', 'olymp.sty', 'problem.tex', 'statements.ftl'}:
                continue
            upload_file_from_path(filepath, 'resource')
        for filepath in get_files(["src/*.cpp", "src/*.c++", "src/*.pas", "src/*.java", "src/*.py", "src/*.dpr"]):
            if os.path.basename(filepath) in {'testlib.pas'}:
                continue
            upload_file_from_path(filepath, 'source')
            if os.path.splitext(os.path.basename(filepath))[0] in {'check', 'checker'}:
                self.set_utility_file(os.path.basename(filepath), 'checker')
            if os.path.splitext(os.path.basename(filepath))[0] in {'validate', 'validator'}:
                self.set_utility_file(os.path.basename(filepath), 'validator')
