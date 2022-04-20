# Copyright (c) Juniper Networks, Inc., 2020 - 2022. All rights reserved.

# Notice and Disclaimer: This code is licensed to you under the GNU General Public License v3.0.
# You may not use this code except in compliance with the License.
# This code is not an official Juniper product.
# You can obtain a copy of the License at https://www.gnu.org/licenses/gpl-3.0.txt

# SPDX-License-Identifier: GPL-3.0-or-later

# Third-Party Code: This code may depend on other components under separate copyright notice and license terms.
# Your use of the source code for those components is subject to the terms and conditions of the respective license as noted in the Third-Party source code file.

import graphistry
import pandasticsearch

class ZTN_Graph():
    def __init__(self, url, user, password):
        self.url = url
        self.user = user
        self.password = password

        ## or via fresh short-lived token below that expires in 1:00:00 after initial generation
        # graphistry.register(api=3, protocol="https", server="hub.graphistry.com", token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im5hdHpiZXJnIiwiaWF0IjoxNjQ2MDc5ODcyLCJleHAiOjE2NDYwODM0NzIsImp0aSI6IjA3MzZlYTA5LWE1MDMtNDYzNy04NDgwLTI5NjRlMzRkODUxZiIsInVzZXJfaWQiOjYzMzEsIm9yaWdfaWF0IjoxNjQ2MDc5ODcyfQ.7GvRglH37_FYWJ73lQ-vTCIRp0X4acY6kzVtll2Bnqk")

    def login(self):
       graphistry.register(api=3, username=self.user, password=self.password)

    def parse_count_data(self, data):