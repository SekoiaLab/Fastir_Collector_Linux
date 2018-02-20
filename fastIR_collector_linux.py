import sys
import socket
from zipfile import ZipFile
import logging
from datetime import datetime
import os
import shutil
import subprocess
import glob
import pwd
import re
import csv
import grp

size_max_log = 10 * 1024 * 1024
start_fs = '/'
skipped_dir = []

if len(skipped_dir):
    skipped_dir = [os.path.join(start_fs, d) for d in skipped_dir]
mime_filter = []

level_debug = logging.INFO

# path file to collects
etc_passwd = os.path.join(start_fs, '/etc/passwd')
etc_shadow = os.path.join(start_fs, '/etc/shadow')
etc_bashrc = os.path.join(start_fs, '/etc/bash.bashrc')
etc_profile = os.path.join(start_fs, '/etc/profile')
etc_cron_rep = os.path.join(start_fs, '/etc/cron.*')
etc_cron = os.path.join(start_fs, '/etc/crontab')
etc_folder_d = os.path.join(start_fs, '/etc/*.d')
# command to launch
netstat = ['netstat', '-apetul']
ss = ['ss', '-tp']
ps = ['ps', '-ewo', '%p,%P,%x,%t,%u,%c,%a']
last = ['last', '-Faixw']
lsof = ['lsof', '-R']
du = ['du', '-sh']
fdisk = ['fdisk', '-l']
hostname = ['hostname']
uname = ['uname', '-r']
ifconfig = ['ifconfig', '-a']
os_version = ['cat', '/proc/version']
whoami = ['who', 'am', 'i']
uname_os_name = ['uname']
lsmod = ['lsmod']
# output
pattern_last_output = "([^\s]+)\s+(\([^\)]*\)|system \S+|\S+)(.+[^\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# header de fichiers output
header_ss = ['State', 'Recv-Q', 'Send-Q', 'Local Address:Port', 'Peer Address:Port', 'Users']
header_last_output = ['User', 'Way of connection', 'Date', 'Remote host']
header_netstat = ['Proto', 'Recv-Q', 'Send-Q', 'Local Address', 'Remote Address', 'State', 'User', 'Inode',
                  'PID/Program name']
header_fs = ['path', 'mime', 'filesize', 'owner', 'group', 'atime', 'mtime', 'ctime', 'inode']
header_lsmod = ['Module', 'Size', 'Used_by_Count', 'Used_by_Modules']

class utils(object):
    def __init__(self, args):
        self.args = args

    def walk(self, path):
        # parcours de tous les fichiers et dossiers a partir de path
        # ajout d'un filtre pour exclure ce qui n'est pas sur le meme device ? (par exemple dans les args mettre all ou juste device)
        pass

    @staticmethod
    def exec_cmd(cmd, raw_res=False):
        cmd_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not raw_res:
            res = []
            for p in cmd_process.stdout:
                res.append(p.replace("\n", ""))
            return res
        else:
            return cmd_process.stdout.read()

    @staticmethod
    def exec_cmd_file(cmd):
        cmd_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return cmd_process.stdout

    @staticmethod
    def open_csv(header, fname):
        writer = csv.DictWriter(open(fname, 'w'), header)
        if hasattr(writer, 'writeheader'):
            writer.writeheader()
        return writer

    @staticmethod
    def writerow(map, writer):
        writer.writerow(map)

    @staticmethod
    def write_to_csv(map, header, fname):
        f = open(fname, "w")
        writer = csv.DictWriter(f, fieldnames=header)
        if hasattr(writer, 'writeheader'):
            writer.writeheader()
        count = 0
        for m in map:
            if count == 0 or m == {}:
                pass
            else:
                writer.writerow(m)
            count += 1

    @staticmethod
    def write_to_file(f, data):
        f = open(f, "w")
        for elem in data:
            f.write(elem)
        f.close()

    @staticmethod
    def list_to_map(keys, data, delimiter=None):
        res = []
        for d in data:
            map = {}
            if delimiter:
                line = d.split(delimiter)
            else:
                line = d
            for j in range(len(line)):
                if len(keys) == len(line):
                    map[keys[j]] = line[j]
            res.append(map)
        return res

    def du(path):
        """disk usage in human readable format (e.g. '2,1GB')"""
        du_cmd = du.append(path)
        return subprocess.check_output(du_cmd).split()[0].decode('utf-8')

    @staticmethod
    def zip_file(list_to_zip, zip_filename, output_dir, logger):
        my_zip = ZipFile(os.path.join(output_dir, zip_filename), 'w', allowZip64=True)
        for path in list_to_zip:
            try:
                my_zip.write(path)
            except Exception as e:
                logger.error(e.strerror + ' ' + path)

        my_zip.close()

    @staticmethod
    def convert_timestamp(timestamp):
        return datetime.fromtimestamp(
                int(timestamp)
        ).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def os_type():
        try:
            return utils.exec_cmd(uname_os_name, True)
        except:
            return "mac"


class FileSystem(object):
    def __init__(self, args):
        self.args = args

    def _check_dir(self, f):
        check_dir = [f.startswith(d) for d in skipped_dir]
        if len(check_dir) == 0:
            return True
        return not any(check_dir)

    def get_infos_fs(self):
        writer = None
        self.args['logger'].info('Start make time line FS')
        for dirName, subdirList, fileList in os.walk(start_fs):
            for f in fileList:
                path = os.path.join(dirName, f)
                if self._check_dir(path):
                    record = self._get_file_metada(path)
                    if not record:
                        continue
                    record['path'] = path
                    cmd = ['file', path]
                    res = utils.exec_cmd(cmd)
                    mime = res[0].split(':')[1].lstrip()
                    record['mime'] = mime
                    if not writer:
                        writer = utils.open_csv(header_fs,
                                                os.path.join(self.args['output_dir'], 'fs.csv'))
                        if hasattr(writer, 'writeheader'):
                            writer.writeheader()
                    writer.writerow(record)
        self.args['logger'].info('Timeline FS done')

    def _get_file_metada(self, fname):
        try:
            stats = os.lstat(fname)
        except:
            stats = None
            return stats
        try:
            pwd_struct = pwd.getpwuid(stats.st_uid)
        except:
            pwd_struct = None

        try:
            grp_struct = grp.getgrgid(stats.st_gid)
        except:
            grp_struct = None

        meta_data = {
            'filesize': stats.st_size,
            'mtime': utils.convert_timestamp(stats.st_mtime),
            'atime': utils.convert_timestamp(stats.st_atime),
            'ctime': utils.convert_timestamp(stats.st_ctime),
            'owner': (stats.st_uid, pwd_struct),
            'group': (stats.st_gid, grp_struct),
            'inode': stats.st_ino,
        }

        if hasattr(stats, 'st_birthtime'):
            meta_data['crtime'] = utils.convert_timestamp(stats.st_birthtime)
        return meta_data


class LiveInformations(object):
    def __init__(self, args=None):
        self.args = args
        self._info_path = os.path.join(self.args["output_dir"], "additionnal_informations.txt")
        self._additional_info = {}

    def get_processes(self):
        # recupere tous les process en cours
        try:
            self.args['logger'].info(' '.join(ps))
            res = utils.exec_cmd(ps)
            header = self._get_header(res, ",")
            map = utils.list_to_map(header, res, ",")
            self.args['logger'].info('Write in csv file %s ' % os.path.join(self.args['output_dir'], "process.csv"))
            utils.write_to_csv(map, header, os.path.join(self.args['output_dir'], "process.csv"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(ps))

    def _get_header(self, data, delimiter, offset=0):
        fields = data[offset].split(delimiter)
        header = []
        for f in fields:
            f = f.replace(" ", "")
            if f != "":
                header.append(f)
        return header

    def _delete_spaces(self, data):
        res_without_spaces = []
        for r in data:
            temp = []
            for value in r.split(' '):
                if value is not "":
                    temp.append(value)
            res_without_spaces.append(temp)
        return res_without_spaces

    def _get_kernel_version(self):
        try:
            self.args['logger'].info(' '.join(uname))
            self._additional_info['kernel'] = utils.exec_cmd(uname, True).rstrip()
        except:
            self.args['logger'].error("%s command failed" % ' '.join(uname))

    def _get_os_infos(self):
        try:
            self.args['logger'].info(' '.join(os_version))
            self._additional_info["os_informations"] = utils.exec_cmd(os_version, True).rstrip()
        except:
            self.args['logger'].error("%s command failed" % ' '.join(os_version))

    def _get_user(self):
        # get user who is logged on
        try:
            self.args['logger'].info(' '.join(whoami))
            self._additional_info["user"] = utils.exec_cmd(whoami, True)
        except:
            self.args['logger'].error("%s command failed" % ' '.join(whoami))

    def _get_network_card(self):
        try:
            self.args['logger'].info(' '.join(ifconfig))
            res = utils.exec_cmd(ifconfig, True).rstrip()
            cards = res.split("\n\n")
            count = 1
            for c in cards:
                li = c.split('\n')
                self._additional_info["network_card_" + str(count)] = li[0] + "\n\t" + li[1] + "\n\t" + li[2]
                count += 1
        except:
            self.args['logger'].error("%s command failed" % ' '.join(ifconfig))

    def _get_hostname(self):
        try:
            self.args['logger'].info(' '.join(hostname))
            self._additional_info['hostname'] = utils.exec_cmd(hostname, True).rstrip()
        except:
            self.args['logger'].error("%s command failed" % ' '.join(hostname))

    def get_network_connections(self):
        # fais un ss -tp
        try:
            self.args['logger'].info(' '.join(ss))
            res = utils.exec_cmd(ss)
            res_without_spaces = self._delete_spaces(res)

            map = utils.list_to_map(header_ss, res_without_spaces)
            self.args['logger'].info('Write in csv file %s ' % os.path.join(self.args['output_dir'], "ss_sockets.csv"))
            utils.write_to_csv(map, header_ss, os.path.join(self.args['output_dir'], "ss_sockets.csv"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(ss))
        try:

            self.args['logger'].info(' '.join(netstat))
            res = utils.exec_cmd(netstat)

            res_without_spaces = self._delete_spaces(res)
            del res_without_spaces[0]
            map = utils.list_to_map(header_netstat, res_without_spaces)
            self.args['logger'].info(
                    'Write in csv file %s ' % os.path.join(self.args['output_dir'], "netstat_sockets.csv"))
            utils.write_to_csv(map, header_netstat, os.path.join(self.args['output_dir'], "netstat_sockets.csv"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(netstat))

    def get_logon(self):
        # recupere tous les utilisateurs qui se sont connectes a la machine ainsi que ceux qui le sont encore
        try:
            res = utils.exec_cmd(last)
            self.args['logger'].info(' '.join(last))
            r_bis = []
            for r in res:
                temp = []
                matchObj = re.match(pattern_last_output, r)
                if matchObj:
                    temp.append(matchObj.group(1))
                    temp.append(matchObj.group(2))
                    temp.append(matchObj.group(3).strip())
                    temp.append(matchObj.group(4))
                if temp is not []:
                    r_bis.append(temp)

            map = utils.list_to_map(header_last_output, r_bis)
            self.args['logger'].info('Write in csv file %s ' % os.path.join(self.args['output_dir'], "logon.csv"))
            utils.write_to_csv(map, header_last_output, os.path.join(self.args['output_dir'], "logon.csv"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(last))

    def get_handle(self):
        try:
            res = utils.exec_cmd_file(lsof)
            self.args['logger'].info(' '.join(lsof))
            utils.write_to_file(os.path.join(self.args["output_dir"], "handle.txt"), res)
            self.args['logger'].info('Write in text file %s ' % os.path.join(self.args['output_dir'], "handles.txt"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(lsof))

    def get_modules(self):
        try:
            self.args['logger'].info(' '.join(lsmod))
            res = utils.exec_cmd(lsmod)
            res_without_spaces = self._delete_spaces(res)
            # Add '-' to module entries that are used by 0 modules
            # so that every entry has same number of fields
            for entry in res_without_spaces:
                if len(entry) == 3:
                    entry.append('-')
            map = utils.list_to_map(header_lsmod, res_without_spaces)
            self.args['logger'].info('Write in csv file %s ' % os.path.join(self.args['output_dir'], "modules.csv"))
            utils.write_to_csv(map, header_lsmod, os.path.join(self.args['output_dir'], "modules.csv"))
        except:
            self.args['logger'].error("%s command failed" % ' '.join(lsmod))

    def get_additionnal_info(self):
        self._get_kernel_version()
        self._get_hostname()
        self._get_network_card()
        self._get_os_infos()
        self._get_user()

        with open(self._info_path, "w") as f:
            for key, value in sorted(self._additional_info.items()):
                f.write(key + ' : ' + value + '\n')


class Dump(object):
    def __init__(self, args):
        self.args = args
        self._homes = self._get_home()

    def _get_home(self):

        homes = []
        if os.path.isfile(etc_passwd):
            f = open(etc_passwd, 'r')
            homes = [line.split(":")[5] for line in f]
            f.close()
        return homes

    def get_temp(self):
        file_to_zip = []
        for dirName, subdirList, fileList in os.walk(os.path.join(start_fs, '/tmp')):
            file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        file_to_zip = list(set(file_to_zip))
        self.args['logger'].info('Zip tmp.zip with %s ' % file_to_zip)
        utils.zip_file(file_to_zip, 'tmp.zip', self.args['output_dir'], self.args['logger'])

    def autorun(self):
        file_to_zip = []
        dir_collect = glob.glob(etc_folder_d)
        cron_dir = glob.glob(etc_cron_rep)
        self.args['logger'].info('Collect %s ' % dir_collect)
        for d in dir_collect:
            for dirName, subdirList, fileList in os.walk(d):
                file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        self.args['logger'].info('Collect %s ' % cron_dir)
        for d in cron_dir:
            for dirName, subdirList, fileList in os.walk(d):
                file_to_zip.extend([os.path.join(dirName, f) for f in fileList])
        file_to_zip.append(etc_cron)
        self.args['logger'].info('Zip file autorun.zip')
        utils.zip_file(list(set(file_to_zip)), 'autorun.zip', self.args['output_dir'], self.args['logger'])

    def collect_users(self):
        list_to_zip = []
        self.args['logger'].info('Collect users')

        if os.path.isfile(etc_passwd):
            list_to_zip.append(etc_passwd)
        if os.path.isfile(etc_shadow):
            list_to_zip.append(etc_shadow)
        if os.path.isfile(etc_bashrc):
            list_to_zip.append(etc_bashrc)
        if os.path.isfile(etc_profile):
            list_to_zip.append(etc_profile)
        for home in self._homes:
            if os.path.exists(home):
                list_to_zip.extend(
                        [p for p in glob.glob(os.path.join(start_fs, os.path.join(home, '.*'))) if os.path.isfile(p)])
        utils.zip_file(list_to_zip, 'users_home.zip', self.args['output_dir'], self.args['logger'])

    def collect_ssh_profile(self):
        self.args['logger'].info('Collect Know Hosts')
        list_knows_host = []
        for home in self._homes:
            if os.path.exists(home):
                list_knows_host.extend(glob.glob(os.path.join(start_fs, os.path.join(home, '.ssh/known_hosts'))))
                if len(list_knows_host) > 0:
                    utils.zip_file(list_knows_host, 'know_hosts.zip', self.args['output_dir'], self.args['logger'])

    def collect_log(self):
        files_list_to_zip = {}
        self.args['logger'].info('Zip of /var/log')
        for dirName, subdirList, fileList in os.walk(os.path.join(start_fs, '/var/log')):
            for fname in fileList:
                absolut_path = os.path.join(dirName, fname)
                size = os.stat(absolut_path).st_size
                if size < size_max_log:
                    files_list_to_zip[os.path.join(dirName, fname)] = size
        files_list_to_zip_sorted = sorted(files_list_to_zip.items(), key=lambda x: x[1])
        utils.zip_file(dict(files_list_to_zip).keys(), 'var_log.zip', self.args['output_dir'], self.args['logger'])
        self.args['logger'].info('Zip of /var log is finished')
        pass

    def dump_dir(self):
        # recupere tous les dossiers que l'on aura mis en arguments
        pass

    def _active_part(self, block, disk):
        for line in block.split("\n"):
            if disk in line and "*" in line:
                return disk

    def _list_disks(self, res):
        disks = []
        for blocks in res:
            matchob = re.match("\n?Dis[a-z]{1,3}\s([^:]+)", blocks)
            if matchob:
                disks.append(matchob.group(1).replace('\xc2\xa0', ''))
        return disks

    def _get_mbr(self, disks):
        for d in disks:
            disk_name = d.replace("/", "_")
            with open(d, "rb") as f:
                with open(os.path.join(self.args['output_dir'], "mbr" + disk_name), "wb") as output:
                    output.write(f.read(512))

    def dump_mbr(self):
        if utils.os_type() == "mac":
            pass
        else:
            self.args['logger'].info('Collect active MBR')
            r = utils.exec_cmd(fdisk, True)
            res = re.split("\\n\\s*\\n", r)
            disks = self._list_disks(res)
            self.args['logger'].debug('Disks name : %s' % str(disks))
            has_active_part = []
            for blocks in res:
                if disks:
                    for d in disks:
                        m = self._active_part(blocks, d)
                        if m:
                            has_active_part.append(m)
            if has_active_part:
                self._get_mbr(has_active_part)


class Factory(object):
    def __init__(self, args):
        self.args = args
        self.profiles = \
            {'fast': {'module': 'fastIR_collector', 'class': [LiveInformations, Dump]},
             'all': {'module': 'fastIR_collector', 'class': [LiveInformations, Dump, FileSystem]},
             'advanced': {'module': 'fastIR_collector', 'class': [LiveInformations, Dump, FileSystem]},
             'dump': {'module': 'fastIR_Collector', 'class': [Dump]}
             }
        pass

    def execute(self):
        for p in self.args['profiles']:
            if p in self.profiles:
                for cl in self.profiles[p]['class']:
                    c = cl(self.args)
                    for attr in dir(c):
                        if attr != 'args' and not attr.startswith('_'):
                            getattr(c, attr)()

        pass


def banner():
    print(r"""
  ______        _   _____ _____
 |  ____|      | | |_   _|  __ \
 | |__ __ _ ___| |_  | | | |__) |
 |  __/ _` / __| __| | | |  _  /
 | | | (_| \__ \ |_ _| |_| | \ \
 |_|  \__,_|___/\__|_____|_|  \_\

     A Fast forensic analysis tool
    """)


def set_logger(args):
    # Stream logger class for printing only INFO level messages
    class InfoStreamHandler(logging.StreamHandler):
        def __init__(self, stream):
            logging.StreamHandler.__init__(self, stream)

    # initiating the logger and the string format
    logger = logging.getLogger("FastIR")
    logger.setLevel(level_debug)
    if 'level_debug' in args:
        logger.setLevel(args['level_debug'])

    log_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # initiating the filehandler
    fh = logging.FileHandler(os.path.join(args["output_dir"], "FastIR.log"), encoding="UTF-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(log_format)
    logger.addHandler(fh)

    # initiatinig the stream handler
    fs = InfoStreamHandler(sys.stdout)
    fs.setFormatter(log_format)
    if 'level_debug' in args:
        fs.setLevel(args['level_debug'])
    logger.addHandler(fs)
    args["logger"] = logger


def parse_command_line():
    """Parse command line arguments and return them in a way that python can use directly"""

    args = {}
    try:
        import argparse
        parser = argparse.ArgumentParser(description="FastIR")

        parser.add_argument("--profiles", dest="profiles",
                            help=(
                                "List of profiles: fast,dump,all"
                                "\n use: --profiles fast or --profiles dump --profiles all"))
        parser.add_argument("--output_dir", dest="output_dir", help="Directory to extract data")
        parser.add_argument("--dir_zip", dest='dir_zip', help='directory to store zip')
        parser.add_argument("--debug", dest="debug", default=False, action='store_true', help="debug level")
        arguments = parser.parse_args()
        if not arguments.output_dir:
            print('No output directory specified. Using "output" as default')
            arguments.output_dir = 'output'
        if not arguments.profiles:
            print('No profile specified. Using "fast" as default')
            arguments.profiles = 'fast'
        args['output_dir'] = arguments.output_dir
        args['dir_zip'] = arguments.dir_zip
        if not arguments.dir_zip:
            args['dir_zip'] = args['output_dir']

        args['profiles'] = arguments.profiles.split(';')

        if arguments.debug:
            args['level_debug'] = logging.DEBUG
    except Exception as e:
        print(e)
        args['output_dir'] = sys.argv[1]
        args['dir_zip'] = sys.argv[2]
        args['profiles'] = sys.argv[3].split(';')
    return args


def create_output_dir(args):
    hostname = socket.gethostname()
    date_collect = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = os.path.join(args['output_dir'], hostname, date_collect)
    try:
        os.makedirs(path)
    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(-1)
    except ValueError:
        print("Could not convert data")
        sys.exit(-1)
    except:
        print("Unexpected error:", sys.exc_info()[0])

    return path


def set_zip_evidences(args):
    path_output_dir = args['output_dir']
    items = path_output_dir.split(os.path.sep)[::-1]

    name_zip_file = items[0] + '_' + items[1] + '.zip'
    zip_path = os.path.join(args['dir_zip'], name_zip_file)
    args['logger'].info('Create zip File %s ' % name_zip_file)
    my_zip = ZipFile(zip_path, 'w', allowZip64=True)

    for dirName, subdirList, fileList in os.walk(path_output_dir, topdown=False):
        for fname in fileList:
            my_zip.write(os.path.join(dirName, fname))
    my_zip.close()
    shutil.rmtree(os.path.dirname(path_output_dir))
    args['logger'].info('Delete folder %s' % path_output_dir)


def main():
    if os.geteuid() != 0:
        print('This program should be run as root.')
        sys.exit(-1)

    args = parse_command_line()
    args['output_dir'] = create_output_dir(args)
    set_logger(args)
    f = Factory(args)
    f.execute()
    set_zip_evidences(args)


pass

if __name__ == '__main__':
    banner()
    main()
