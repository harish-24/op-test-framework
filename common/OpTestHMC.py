#!/usr/bin/env python2
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2018
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# @package OpTestHMC
#  This class can contain common functions which are useful for
#  FSP_PHYP (HMC) platforms

import os
import sys
import time
import pexpect
import subprocess

import OpTestConfiguration
from common.OpTestError import OpTestError
from common.OpTestSSH import OpTestSSH
from common.OpTestHost import OpTestHost
from common.Exceptions import CommandFailed

from common import OPexpect

import logging
import OpTestLogger
log = OpTestLogger.optest_logger_glob.get_logger(__name__)

WAITTIME = 15


class OpHmcState():
    '''
    This class is used as an enum as to what state op-test *thinks* the host is in.
    These states are used to drive a state machine in OpTestSystem.
    '''
    NOT_ACTIVE = 'Not Activated'
    RUNNING = 'Running'
    SHUTTING = 'Shutting Down'
    OF = 'Open Firmware'
    STARTING = 'Starting'
    NA = 'Not Available'


class OpManagedState():
    '''
    This class is used as an enum as to what state op-test *thinks* the host is in.
    These states are used to drive a state machine in OpTestSystem.
    '''
    OPERATING = 'Operating'
    INIT = 'Initializing'
    OFF = 'Power Off'
    PROG_OFF = 'Power Off In Progress'


class OpTestHMC():

    '''
    This class contains the modules to perform various HMC operations on an LPAR.
    The Host IP, username and password of HMC have to be passed to the class intially
    while creating the object for the class.
    '''

    def __init__(self, hmc_ip, user_name, password, scratch_disk="", proxy="",
                 logfile=sys.stdout, managed_system=None, lpar_name=None,
                 lpar_prof=None, lpar_vios=None, lpar_user=None, lpar_password=None,
                 check_ssh_keys=False, known_hosts_file=None):
        self.hmc_ip = hmc_ip
        self.user = user_name
        self.passwd = password
        self.logfile = logfile
        self.system = managed_system
        self.system = managed_system
        self.check_ssh_keys = check_ssh_keys
        self.known_hosts_file = known_hosts_file
        self.lpar_name = lpar_name
        self.lpar_prof = lpar_prof
        self.lpar_user = lpar_user
        self.lpar_password = lpar_password
        self.lpar_vios = lpar_vios
        self.lpar_con = None
        self.vterm = False
        self.conf = OpTestConfiguration.conf
        self.ssh = OpTestSSH(hmc_ip, user_name, password, logfile=self.logfile,
                             check_ssh_keys=check_ssh_keys,
                             known_hosts_file=known_hosts_file)
        self.scratch_disk = scratch_disk
        self.proxy = proxy
        self.scratch_disk_size = None

    def hostname(self):
        return self.hmc_ip

    def username(self):
        return self.user

    def password(self):
        return self.passwd

    def set_system(self, system):
        self.ssh.set_system(system)

    def get_scratch_disk(self):
        return self.scratch_disk

    def run_command(self, i_cmd, timeout=15):
        return self.ssh.run_command(i_cmd, timeout)

    def deactivate_lpar_console(self):
        self.run_command("rmvterm -m %s -p %s" % (self.system, self.lpar_name), timeout=10)

    def poweroff_system(self):
        if self.get_system_state() != OpManagedState.OPERATING:
            raise OpTestError('Managed Systen not in Operating state')
        self.run_command("chsysstate -m %s -r sys -o off" % self.system)
        self.wait_system_state(OpManagedState.OFF)

    def poweron_system(self):
        if self.get_system_state() != OpManagedState.OFF:
            raise OpTestError('Managed Systen not is Power off state!')
        self.run_command("chsysstate -m %s -r sys -o on" % self.system)
        self.wait_system_state()
        if self.lpar_vios:
            log.debug("Starting VIOS %s" % self.lpar_vios)
            self.poweron_lpar(vios=True)

    def poweroff_lpar(self):
        if self.get_lpar_state() in [OpHmcState.NOT_ACTIVE, OpHmcState.NA]:
            log.info('LPAR Already powered-off!')
            return
        self.run_command("chsysstate -m %s -r lpar -n %s -o shutdown --immed" %
                         (self.system, self.lpar_name))
        self.wait_lpar_state(OpHmcState.NOT_ACTIVE)

    def poweron_lpar(self, runtime=False, vios=False):
        if self.get_lpar_state(vios) == OpHmcState.RUNNING:
            log.info('LPAR Already powered on!')
            return
        lpar_name = self.lpar_name
        if vios:
            lpar_name = self.lpar_vios
        cmd = "chsysstate -m %s -r lpar -n %s -o on" % (self.system, lpar_name)

        if not vios:
            if self.lpar_prof:
                cmd = "%s -f %s" % (cmd, self.lpar_prof)

        self.wait_lpar_state(OpHmcState.NOT_ACTIVE, vios=vios)
        self.run_command(cmd)
        self.wait_lpar_state(vios=vios)
        if runtime:
            self.wait_console_prompt()
            self.close_console(self.lpar_con)

    def get_lpar_state(self, vios=False):
        lpar_name = self.lpar_name
        if vios:
            lpar_name = self.lpar_vios
        state = self.run_command(
            'lssyscfg -m %s -r lpar --filter lpar_names=%s -F state' % (self.system, lpar_name))
        return state[-1]

    def get_system_state(self):
        state = self.run_command(
            'lssyscfg -m %s -r sys -F state' % self.system)
        return state[-1]

    def wait_lpar_state(self, exp_state=OpHmcState.RUNNING, vios=False, timeout=WAITTIME):
        state = self.get_lpar_state(vios)
        count = 0
        while state != exp_state:
            state = self.get_lpar_state(vios)
            log.info("Current state: %s" % state)
            time.sleep(timeout)
            count += 1
            if count > 120:
                raise OpTestError("Time exceeded for reaching %s" % exp_state)

    def wait_system_state(self, exp_state=OpManagedState.OPERATING, timeout=WAITTIME):
        state = self.get_system_state()
        count = 0
        while state != exp_state:
            state = self.get_system_state()
            log.info("Current state: %s" % state)
            time.sleep(timeout)
            count += 1
            if count > 60:
                raise OpTestError("Time exceeded for reaching %s" % exp_state)

    def console_run_command(self, console, cmd, timeout=60):
        if console is None:
            console = self.get_console()

        try:
            console.send(cmd)
            console.send('\r')
            output = console.before
            console.sendline("echo $?")
            console.send('\r')
            # Time to accumulate both outputs
            time.sleep(1)
            rc = console.expect(["\[console-pexpect\]#$"], timeout=timeout)
            if rc != 0:
                exitcode = int(console.before)
                log.debug("# LAST COMMAND EXIT CODE %d (%s)" % (exitcode, repr(console.before)))
        except pexpect.TIMEOUT as e:
            log.debug(e)
            log.debug("# TIMEOUT waiting for command to finish.")
            log.debug("# Attempting to control-c")
            try:
                console.sendcontrol('c')
                rc = console.expect(["\[console-pexpect\]#$"], 10)
                if rc == 0:
                    raise CommandFailed(cmd, "TIMEOUT", -1)
            except pexpect.TIMEOUT:
                log.error("# Timeout trying to kill timed-out command.")
                log.error("# Failing current command and attempting to continue")
                self.deactivate_lpar_console()
                raise CommandFailed("console", "timeout", -1)
            raise e

        if rc == 0:
            res = console.before
            res = res.split(cmd)
            return res[-1].splitlines()[1:-2]
        else:
            res = output
            res = res.splitlines()
            if exitcode != 0:
                raise CommandFailed(cmd, res, exitcode)
            return res

    def get_console(self, skip_login=False):
        console = self.wait_console_prompt(self.lpar_user, self.lpar_password, skip_login=skip_login)
        console.sendline('PS1=[console-pexpect]\#')
        console.send('\r')
        l_rc = console.expect("\[console-pexpect\]#$")
        if l_rc == 0:
            log.debug("Shell prompt changed")
        else:
            raise Exception("Failed during change of shell prompt")
        return console

    def check_vterm(self):
        """
        spawn_obj.sendline("mkvterm -m %s -p %s" %
                         (self.system, self.lpar_name))
        spawn_obj.send('\r')
        i = spawn_obj.expect(
            ["already open", "Open Completed.", pexpect.EOF, pexpect.TIMEOUT], timeout=60)
        if i == 0:
            return False
        elif i == 1:
            return True
        else:
            raise OpTestError(
                'Console object is a EOF, close and spawn a new one!')
        """
        return self.vterm

    def wait_console_prompt(self, username=None, password=None, skip_login=False):
        if self.get_lpar_state() == OpHmcState.OF:
            raise OpTestError(
                'LPAR set to boot to SMS menu. Please change to "Normal" boot')
        log.info("De-activating the console")

        self.deactivate_lpar_console()
        #if self.lpar_con:
        #    self.close_console(self.lpar_con)
        command = "sshpass -p %s ssh -p 22 -l %s %s -o PubkeyAuthentication=no"\
                  " -o afstokenpassing=no -q -o 'UserKnownHostsFile=/dev/null'"\
                  " -o 'StrictHostKeyChecking=no'"
        self.lpar_con = OPexpect.spawn(
                command % (self.passwd, self.user, self.hmc_ip))
        self.wait_lpar_state()
        log.info("Opening the LPAR console")
        self.vterm = True
        self.lpar_con.sendline("mkvterm -m %s -p %s" %
                               (self.system, self.lpar_name))
        self.lpar_con.send('\r')
        time.sleep(2)
        i = self.lpar_con.expect(
            ["Open Completed.", pexpect.EOF, pexpect.TIMEOUT], timeout=60)
        self.lpar_con.send('\r')
        self.lpar_con.logfile = sys.stdout
        self.lpar_con.logfile_read = OpTestLogger.FileLikeLogger(log)
        if i == 0:
            if skip_login:
                log.debug("Skipping login")
                return self.lpar_con
            # Assuming 'Normal' boot set in LPAR profile
            # We wait for upto 500 seconds for LPAR to boot to OS
            log.debug("Waiting for login screen")
            i = self.lpar_con.expect(
                ["login:", "\[console-pexpect\]#$", pexpect.TIMEOUT], timeout=500)
            if i == 0:
                log.debug("System has booted")
                if username and password:
                    self.lpar_con.sendline(username)
                    self.lpar_con.send('\r')
                    i = self.lpar_con.expect(
                        ["Password:", pexpect.TIMEOUT], timeout=60)
                    if i == 0:
                        self.lpar_con.sendline(password)
                        self.lpar_con.send('\r')
                        i = self.lpar_con.expect(
                            ["Last login", "incorrect", pexpect.TIMEOUT], timeout=60)
                        if i == 0:
                            log.info('Logged in to console')
                            time.sleep(5)
                            return self.lpar_con
                        elif i == 1:
                            raise OpTestError("Wrong Credentials for host")
                        else:
                            raise OpTestError("Upexpected return")
                time.sleep(5)
                return self.lpar_con
            elif i == 1:
                # Assuming console already logged in !"
                time.sleep(5)
                return self.lpar_con
            else:
                log.error("%s %s" % (i, self.lpar_con.before))
                raise OpTestError("Console in different state")
        elif i == 1:
             self.wait_console_prompt()
        else:
            raise OpTestError("Check the lpar activate command")

    def close_console(self, console):
        console.send('~.')
        self.vterm = False
        time.sleep(5)
        console.close()
