from .common import *


def process_upload_tests(options):
    if not load_session_with_options(options):
        fatal('No session known. Use relogin or init first.')
    global_vars.problem.import_tests_by_mask(directory=options.directory, mask=options.mask)


def add_parser(subparsers):
    parser = subparsers.add_parser(
            'import_tests',
            help="Import (upload) tests from directory by given mask"
    )
    parser.add_argument("-d", "--directory", dest="directory",
                        help="provide the folder where the tests are")
    parser.add_argument("-m", "--mask", dest="mask", default='*',
                        help="set a name's mask for tests, default is '*'")
    parser.set_defaults(func=process_upload_tests)
