# Copyright 2020 The SODA Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import hashlib

import paramiko
import six
from oslo_log import log

from delfin import exception

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class StorageDriver(object):

    def __init__(self, **kwargs):
        """
        :param kwargs:  A dictionary, include access information. Pay
            attention that it's not safe to save username and password
            in memory, so suggest each driver use them to get session
            instead of save them in memory directly.
        """
        self.storage_id = kwargs.get('storage_id', None)

    @abc.abstractmethod
    def get_storage(self, context):
        """Get storage device information from storage system"""
        pass

    @abc.abstractmethod
    def list_storage_pools(self, context):
        """List all storage pools from storage system."""
        pass

    @abc.abstractmethod
    def list_volumes(self, context):
        """List all storage volumes from storage system."""
        pass

    @abc.abstractmethod
    def add_trap_config(self, context, trap_config):
        """Config the trap receiver in storage system."""
        pass

    @abc.abstractmethod
    def remove_trap_config(self, context, trap_config):
        """Remove trap receiver configuration from storage system."""
        pass

    @abc.abstractmethod
    def parse_alert(self, context, alert):
        """Parse alert data got from snmp trap server."""
        pass

    @abc.abstractmethod
    def clear_alert(self, context, alert):
        """Clear alert from storage system."""
        pass

    @staticmethod
    def get_ssh_key(context, host, port):
        """Get remote host key for ssh protocol.
        :param host: ip or domain name of the remote device.
        :param port: port for ssh connection.
        :return: returns a dict with the following fields:
            key: public key of the remote host.
            type: key type, like rsa, ecdsa, ed25519.
            fingerprint: the fingerprint of the key.
        """
        try:
            trans = paramiko.Transport((host, port))
            trans.start_client()
            host_key = trans.get_remote_server_key()
            trans.close()
        except paramiko.ssh_exception.SSHException as e:
            LOG.error(e)
            msg = "Unable to connect to {0}:{1}".format(host, port)
            raise exception.SSHConnectionFailed(msg)

        md5hash = hashlib.md5(host_key.asbytes())
        hash_str = md5hash.hexdigest()
        hash_len = len(hash_str)
        step = hash_len // 2
        fingerprint = ""
        # convert abcdef to ab:cd:ef
        for i in range(step):
            if i == 0:
                fingerprint = hash_str[0:2]
            else:
                fingerprint = fingerprint + ":" + hash_str[i * 2:i * 2 + 2]

        ssh_key = {
            "type": host_key.get_name(),
            "key": host_key.get_base64(),
            "fingerprint": fingerprint
        }
        return ssh_key
