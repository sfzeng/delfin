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
import re
from delfin import db
from delfin.api import validation
from delfin.api.common import wsgi
from delfin.api.schemas import access_info as schema_access_info
from delfin.api.views import access_info as access_info_viewer
from delfin.common import constants
from delfin.drivers import api as driverapi
from oslo_log import log
from delfin import exception

LOG = log.getLogger(__name__)


class AccessInfoController(wsgi.Controller):

    def __init__(self):
        super(AccessInfoController, self).__init__()
        self._view_builder = access_info_viewer.ViewBuilder()
        self.driver_api = driverapi.API()

    def show(self, req, id):
        """Show access information by storage id."""
        ctxt = req.environ['delfin.context']
        access_info = db.access_info_get(ctxt, id)
        return self._view_builder.show(access_info)

    @validation.schema(schema_access_info.update)
    def update(self, req, id, body):
        """Update storage access information."""
        ctxt = req.environ.get('delfin.context')
        access_info = db.access_info_get(ctxt, id)
        for access in constants.ACCESS_TYPE:
            if not body.get(access):
                body[access] = None
        access_info.update(body)
        access_info = self.driver_api.update_access_info(ctxt, access_info)

        return self._view_builder.show(access_info)


def create_resource():
    return wsgi.Resource(AccessInfoController())


class SSHController(wsgi.Controller):
    def __init__(self):
        super(SSHController, self).__init__()
        self._view_builder = access_info_viewer.ViewBuilder()
        self.driver_api = driverapi.API()

    def index(self, req):
        """Get remote host key for ssh protocol."""
        ctxt = req.environ.get('delfin.context')
        query_params = {}
        query_params.update(req.GET)
        host, port = self._check_input(query_params.get('host'),
                                       query_params.get('port'))
        LOG.info("host:{0}, port:{1}".format(host, port))

        ssh_key = self.driver_api.get_ssh_key(ctxt, host, port)
        LOG.info("key:{0}, key_type:{1}, fingerprint:{2}".format(
            ssh_key.get("key"),
            ssh_key.get("type"),
            ssh_key.get("fingerprint")))
        return ssh_key

    def _check_input(self, host, port):
        if host is None:
            raise exception.InvalidInput('Query parameter host is required.')
        if len(host) > 255 or re.match('^[a-zA-Z0-9-_.:]*$', host) is None:
            raise exception.InvalidInput('Host is invalid.')

        if port is None:
            # Default port for ssh is 22.
            port = 22
        else:
            try:
                port = int(port)
                if port > 65535 or port < 0:
                    raise exception.InvalidInput('Port is invalid.')
            except ValueError:
                raise exception.InvalidInput('Port is invalid.')

        return host, port


def create_ssh_resource():
    return wsgi.Resource(SSHController())
