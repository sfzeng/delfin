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

from unittest import mock

from delfin import db
from delfin import exception
from delfin import test
from delfin.api.v1.access_info import AccessInfoController, SSHController
from delfin.tests.unit.api import fakes


class TestAccessInfoController(test.TestCase):

    def setUp(self):
        super(TestAccessInfoController, self).setUp()
        self.driver_api = mock.Mock()
        self.controller = AccessInfoController()
        self.ssh_controller = SSHController()
        self.mock_object(self.controller, 'driver_api', self.driver_api)

    def test_show(self):
        self.mock_object(
            db, 'access_info_get',
            fakes.fake_access_info_show)
        req = fakes.HTTPRequest.blank(
            '/storages/865ffd4d-f1f7-47de-abc3-5541ef44d0c1/access-info')

        res_dict = self.controller.show(
            req, '865ffd4d-f1f7-47de-abc3-5541ef44d0c1')
        expctd_dict = {
            "model": "fake_driver",
            "vendor": "fake_storage",
            "storage_id": "865ffd4d-f1f7-47de-abc3-5541ef44d0c1",
            "rest_access": {
                "host": "10.0.0.0",
                "port": 1234,
                "username": "admin"
            },
            "ssh_access": None,
            "extra_attributes": {
                "array_id": "0001234567897"
            },
            "created_at": "2020-06-15T09:50:31.698956",
            "updated_at": "2020-06-15T09:50:31.698956"
        }

        self.assertDictEqual(expctd_dict, res_dict)

    def test_show_with_invalid_id(self):
        self.mock_object(
            db, 'access_info_get',
            mock.Mock(side_effect=exception.AccessInfoNotFound('fake_id')))
        req = fakes.HTTPRequest.blank('/storages/fake_id/access-info')
        self.assertRaises(exception.AccessInfoNotFound,
                          self.controller.show,
                          req, 'fake_id')

    def test_access_info_update(self):
        self.mock_object(
            db, 'access_info_get',
            fakes.fake_access_info_show)

        fake_access_info = fakes.fake_update_access_info(None, None, None)
        self.mock_object(
            self.controller.driver_api, 'update_access_info',
            mock.Mock(return_value=fake_access_info))

        body = {
            'rest_access': {
                'username': 'admin_modified',
                'password': 'abcd_modified',
                'host': '10.0.0.0',
                'port': 1234
            },
            'extra_attributes': {'array_id': '0001234567891'}
        }
        req = fakes.HTTPRequest.blank(
            '/storages/865ffd4d-f1f7-47de-abc3-5541ef44d0c1/access-info')
        res_dict = self.controller.update(
            req, '865ffd4d-f1f7-47de-abc3-5541ef44d0c1', body=body)
        expctd_dict = {
            "model": "fake_driver",
            "vendor": "fake_storage",
            "storage_id": "865ffd4d-f1f7-47de-abc3-5541ef44d0c1",
            "rest_access": {
                "username": "admin_modified",
                "host": "10.0.0.0",
                "port": 1234
            },
            "ssh_access": None,
            "extra_attributes": {
                "array_id": "0001234567897"
            },
            "created_at": "2020-06-15T09:50:31.698956",
            "updated_at": "2020-06-15T09:50:31.698956"
        }
        self.assertDictEqual(expctd_dict, res_dict)

    def test_get_key_with_invalid_input(self):
        self.mock_object(
            self.ssh_controller.driver_api, 'get_ssh_key',
            mock.Mock(side_effect=exception.InvalidInput('Port is invalid.')))
        req = fakes.HTTPRequest.blank('/ssh-key/?port=22')
        self.assertRaises(exception.InvalidInput,
                          self.ssh_controller.get,
                          req)

    def test_get_key(self):
        fake_ssh_key_info = fakes.fake_ssh_key_info(None, None)
        self.mock_object(
            self.ssh_controller.driver_api, 'get_ssh_key',
            mock.Mock(return_value=fake_ssh_key_info))

        expctd_dict = {
            'key': 'AAAAC3NzaC1lZDI1NTE5AAAAIF1SjI+YnvvSVqqOpuPkJvDUk539S'
                   'UnxdTgy2cKcMPjf',
            'type': 'ssh-ed25519',
            'fingerprint': '73:d8:34:18:70:2a:ae:d8:1c:a5:44:40:ef:50:d0:63'
        }

        req = fakes.HTTPRequest.blank('/ssh-key/?host=10.0.0.1&port=22')
        res_dict = self.ssh_controller.get(req)
        self.assertDictEqual(expctd_dict, res_dict)
