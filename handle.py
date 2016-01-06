# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from ovs.db import idl
from ryu.lib.packet.bgp import IPAddrPrefix
from ryu.lib.packet.bgp import _PathAttribute
from ryu.lib.packet.bgp import BGPPathAttributeOrigin
from ryu.lib.packet.bgp import BGPPathAttributeAsPath
from ryu.lib.packet.bgp import BGPPathAttributeMultiExitDisc
from ryu.lib.packet.bgp import BGPPathAttributeNextHop
from ryu.lib.packet.bgp import BGPPathAttributeCommunities

from lib import utils
from lib import transaction
from api import gobgp_pb2 as api

log = logging.getLogger('handler')


class OpsHandler():
    def __init__(self, idl, conn):
        self.router_id = None
        self.neighbors = []
        self.idl = idl
        self.conn = conn
        self.timeout = 5

    def set_handler(self, gobgp_handler):
        self.g_hdr = gobgp_handler

    def handle_update(self):

        self.vrf_update()

        self.bgp_router_update()

        self.bgp_neighbor_update()

        self.bgp_route_update()

    def vrf_update(self):
        try:
            asn, uuid = self.get_bgp_router_uuid()
            log.debug('Recv global config from ops: as={0}, uuid={1}'.format(asn, uuid))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))
            del_global_config_arguments = {'operation': api.DEL}
            self.g_hdr.mod_global_config(del_global_config_arguments)
            log.debug('Send global config to gobgp: type=del')

            self.router_id = None
            self.neighbors = []
        return

    def bgp_router_update(self):
        rows = self.idl.tables['BGP_Router'].rows.values()
        if len(rows) < 1:
            return
        try:
            asn, uuid = self.get_bgp_router_uuid()
            log.debug('Recv global config from ops: as={0}, uuid={1}'.format(asn, uuid))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))
            return

        # Register the router id
        router_id = utils.get_column_value(rows[0], 'router_id')
        if len(router_id) > 0:
            if self.router_id is None:
                # grpc request: add global config
                bgp_conf = {'as': asn, 'router_id': router_id}
                add_global_config_arguments = {
                    'operation': api.ADD,
                    'global': api.Global(**bgp_conf)
                }
                self.g_hdr.mod_global_config(add_global_config_arguments)
                log.debug('Send global config gogbp: type=add, router_id={0}'.format(router_id))
                self.router_id = router_id
            else:
                if router_id == '0.0.0.0':
                    # grpc request: remove global config
                    del_global_config_arguments = {'operation': api.DEL}
                    self.g_hdr.mod_global_config(del_global_config_arguments)

                    log.debug('Send global config to gobgp: type=del')
                    self.router_id = None
                elif router_id != self.router_id:
                    # grpc request: change global config
                    bgp_conf = {'as': asn, 'router_id': router_id}
                    mod_global_config_arguments = {
                        'operation': api.ADD,
                        'global': api.Global(**bgp_conf)
                    }
                    self.g_hdr.mod_global_config(mod_global_config_arguments)

                    log.debug('Send global config to gobgp: type=mod, router_id={0}'.format(router_id))
                    self.router_id = router_id
                else:
                    log.info('Router id not change')
        else:
            log.info('Router id is not configured yet')

        if len(self.neighbors) > 0:
            new_neighbors = utils.get_column_value(rows[0], 'bgp_neighbors')
            log.debug('Recv neighbor config from ops: neighbors={0}'.format(new_neighbors))
            for n in self.neighbors:
                if n not in new_neighbors:
                    # grpc request: remove neighbor
                    peer_conf = {'conf': api.PeerConf(neighbor_address=n)}
                    del_neighbor_config_arguments = {
                        'operation': api.DEL,
                        'peer': api.Peer(**peer_conf)
                    }
                    self.g_hdr.mod_neighbor_config(del_neighbor_config_arguments)
                    log.debug('Send neighbor config to gogbp: type=del, addrs={0}'.format(n))
            self.neighbors = new_neighbors.keys()

    def bgp_neighbor_update(self):
        rows = self.idl.tables['BGP_Neighbor'].rows.values()
        if len(rows) < 1:
            return

        try:
            neighbors = self.get_bgp_neighbor_uuids()
            log.debug('Recv neighbor config from ops: neighbors={0}'.format(neighbors))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))
            return

        # Register the neighbor
        remote_ass = {}
        for row in rows:
            uuid = utils.get_column_value(row, '_uuid')
            remote_ass[uuid] = utils.get_column_value(row, 'remote_as')
        if len(remote_ass) > 0:
            for nk, nv in neighbors.items():
                if nk in remote_ass:
                    # grpc request: remove neighbor
                    peer_conf = {'conf': api.PeerConf(neighbor_address=nv, peer_as=remote_ass[nk])}
                    add_neighbor_config_arguments = {
                        'operation': api.ADD,
                        'peer': api.Peer(**peer_conf)
                    }
                    self.g_hdr.mod_neighbor_config(add_neighbor_config_arguments)
                    log.debug('Send neighbor config to gobgp: type=add, addr={0}, remote_as={1}'.format(nv, remote_ass[nk]))

            self.neighbors = neighbors.values()

    def bgp_route_update(self):
        pass

    def get_bgp_router_uuid(self):
        rows = self.idl.tables['VRF'].rows.values()

        if len(rows) < 1:
            raise Exception('VRF table not found')
        name = utils.get_column_value(rows[0], 'name')
        if name == 'vrf_default':
            routers = utils.get_column_value(rows[0], 'bgp_routers')
            if len(routers) < 1:
                raise Exception('No bgp router configured')
            if len(routers) > 1:
                raise Exception('Default vrf has multiple bgp router setting')
            for k in routers.keys():
                asn = k
                uuid = utils.get_column_value(routers[asn], '_uuid')
                return asn, uuid

    def get_bgp_neighbor_uuids(self):
        rows = self.idl.tables['BGP_Router'].rows.values()
        if len(rows) < 1:
            raise Exception('BGP_Router table not found')
        neighbors = utils.get_column_value(rows[0], 'bgp_neighbors')
        neighbor_dict = {}
        if len(neighbors) < 1:
            raise Exception('No bgp neighbor configured')
        for addr in neighbors.keys():
            uuid = utils.get_column_value(neighbors[addr], '_uuid')
            neighbor_dict[uuid] = addr
        return neighbor_dict

    def mod_bgp_path(self, bgp_path):
        def commit_f():
            operation = None
            while True:
                txn = idl.Transaction(self.idl)
                if bgp_path['is_withdraw']:
                    operation = 'del'
                    rows = self.idl.tables['BGP_Route'].rows.values()
                    for row in rows:
                        if utils.get_column_value(row, 'prefix') == bgp_path['prefix']:
                            operation = 'del'
                            prefix_uuid = utils.get_column_value(row, '_uuid')
                            self.idl.tables['BGP_Route'].rows[prefix_uuid].delete()

                else:
                    operation = 'add'
                    row_nh = utils.row_by_value(self.idl, 'BGP_Nexthop', 'ip_address', bgp_path['nexthop'])
                    if not row_nh:
                        row_nh = txn.insert(self.idl.tables['BGP_Nexthop'])
                        row_nh.ip_address = bgp_path['nexthop']
                        row_nh.type = 'unicast'

                    row_path = txn.insert(self.idl.tables['BGP_Route'])
                    row_path.address_family = 'ipv4'
                    row_path.bgp_nexthops = row_nh
                    row_path.distance = []
                    row_path.metric = 0
                    row_path.path_attributes = bgp_path['bgp_pathattr']
                    row_path.peer = 'Remote announcement'
                    row_path.prefix = bgp_path['prefix']
                    row_path.sub_address_family = 'unicast'
                    row_path.vrf = self.idl.tables['VRF'].rows.values()[0]

                status = txn.commit_block()
                seqno = self.idl.change_seqno
                if status == txn.TRY_AGAIN:
                    log.error("OVSDB transaction returned TRY_AGAIN, retrying")
                    utils.wait_for_change(
                        self.idl, self.timeout, seqno)
                    continue
                elif status == txn.ERROR:
                    log.error("OVSDB transaction returned ERROR: {0}".format(txn.get_error()))
                elif status == txn.ABORTED:
                    log.error("Transaction aborted")
                    return
                elif status == txn.UNCHANGED:
                    log.error("Transaction caused no change")

                break

            if operation is None:
                log.warn('route is not exist in ops: prefix={0}'.format(bgp_path['prefix']))
            else:
                log.debug('Send bgp route to ops: type={0}, prefix={1}'.format(operation, bgp_path['prefix']))
        txn = transaction.Transaction(commit_f)
        result = txn.commit(self.conn)
        log.debug(result)


def grpc_request(f):
    def wrapper(*args):
        try:
            f(*args)
        except Exception as e:
            if hasattr(e, 'details'):
                log.warn('faild grpc request: {0}'.format(e.details))
            else:
                log.warn('faild grpc request: {0}'.format(e))
    return wrapper


class GobgpHandler():
    def __init__(self, g_conn):
        self.g_conn = g_conn
        self.timeout = 3
        self.monitor_timeout = 1000

    def set_handler(self, ops_handler):
        self.o_hdr = ops_handler

    @grpc_request
    def mod_global_config(self, arguments):
        response = self.g_conn.ModGlobalConfig(
                api.ModGlobalConfigArguments(**arguments),
                self.timeout)
        if response:
            log.debug('grpc response: {0}'.format(response))

    @grpc_request
    def mod_neighbor_config(self, arguments):
        response = self.g_conn.ModNeighbor(
            api.ModNeighborArguments(**arguments),
            self.timeout)
        if response:
            log.debug('grpc response: {0}'.format(response))

    @grpc_request
    def monitor_bestpath_chenged(self, arguments):
        ribs = self.g_conn.MonitorBestChanged(
            api.Arguments(**arguments),
            self.monitor_timeout)
        for rib in ribs:
            for path in rib.paths:
                nlri = IPAddrPrefix.parser(path.nlri)
                prefix = nlri[0].prefix
                log.debug('Recv bgp route from gobgp: prefix={0}, withdraw={1}'.format(prefix, path.is_withdraw))
                bgp_path = {'prefix': prefix,
                            'metric': 0,
                            'is_withdraw': path.is_withdraw}
                bgp_pathattr = {'BGP_uptime': '',
                                'BGP_iBGP': '',
                                'BGP_flags': '',
                                'BGP_internal': '',
                                'BGP_loc_pref': '0'}
                for pattr in path.pattrs:
                    path_attr = _PathAttribute.parser(pattr)
                    if isinstance(path_attr[0], BGPPathAttributeOrigin):
                        origin = path_attr[0].value
                        if origin == 0:
                            bgp_pathattr['BGP_origin'] = 'i'
                        elif origin == 1:
                            bgp_pathattr['BGP_origin'] = 'e'
                        else:
                            bgp_pathattr['BGP_origin'] = '?'
                    elif isinstance(path_attr[0], BGPPathAttributeAsPath):
                        if path_attr[0].type == 2:
                            bgp_pathattr['BGP_AS_path'] = '{0}'.format(path_attr[0].value[0][0])
                    elif isinstance(path_attr[0], BGPPathAttributeMultiExitDisc):
                        bgp_path['BGP_MED'] = path_attr[0].value
                    elif isinstance(path_attr[0], BGPPathAttributeNextHop):
                        bgp_path['nexthop'] = path_attr[0].value
                    elif isinstance(path_attr[0], BGPPathAttributeCommunities):
                        communities = []
                        for community in path_attr[0].communities:
                            communities.append(community)
                        bgp_pathattr['BGP_Community'] = ','.join(communities)
                bgp_path['bgp_pathattr'] = bgp_pathattr
                self.o_hdr.mod_bgp_path(bgp_path)
