from pandas.core.frame import DataFrame
from netaddr import *

import pandas as pd
import pyshark

class Mapper():

    broadcast_addresses = ['0x0000fffc', '0x0000fffd', '0x0000ffff']

    def __init__(self, df: DataFrame):
        self.df = df

    def get_diff(self, group):
        return 
        
    def _add_src(self, packet):
        return  packet.zbee_nwk.src \
        if 'zbee_nwk' in packet and \
        'src' in packet.zbee_nwk.field_names and \
        packet.zbee_nwk.src != self.devices['ZC'] \
        else \
        packet.wpan.src16 \
        if 'src16' in packet.wpan.field_names and \
        packet.wpan.src16 != self.devices['ZC'] \
        else None

    # Set device value
    def set_device(self, x):

        if any(x == ba for ba in self.broadcast_addresses):
            return 'B'

        if x == self.devices['ZC']:
            return 'ZC'

        return 'ZR' if x in self.devices['ZR'] \
                else 'ZED' \
                if x in self.devices['ZED'] \
                else 'ZED'

    def fetch_device_types(self, pcapfile):
        # Three device types:
        # Zigbee Coordinator
        # Zigbee Router
        # Zigbee End self.devices

        self.pcapfile = pcapfile

        self.devices =  {
                        "ZC": "0x00000000",
                        "ZR": set(),
                        "ZED": set(),
                    }

        try:
            ## Fetch all data_req
            #
            displayfilter = "wpan.cmd == 0x04"
            data_req = pyshark.FileCapture(pcapfile, display_filter=displayfilter)

            for packet in data_req:
                self.devices['ZED'].add(self._add_src(packet))

                self.devices['ZR'].add( packet.zbee_nwk.dst
                                        if 'zbee_nwk' in packet and
                                        'dst' in packet.zbee_nwk.field_name and 
                                        packet.zbee_nwk.dst != self.devices['ZC']
                                        else 
                                        packet.wpan.dst16
                                        if 'dst16' in packet.wpan.field_names and
                                        packet.wpan.dst16 != self.devices['ZC']
                                        else None
                                        )

            data_req.close()
            #
            ## END

            ## Confirm all ZR self.devices
            #
            displayfilter = "(zbee_nwk.frame_type == 0x1) && (zbee_nwk.radius == 1) && (zbee_nwk.dst == 0xfffc)"
            link_status = pyshark.FileCapture(pcapfile, display_filter=displayfilter)

            for packet in link_status:
                self.devices['ZR'].add(self._add_src(packet))

            link_status.close()
            #
            ## END

            ## Confirm all ZR self.devices
            #
            displayfilter = "(zbee_nwk.src_route == 1)"
            route_1_devices = pyshark.FileCapture(pcapfile, display_filter=displayfilter)

            try:
                potential_zr = {packet.zbee_nwk.dst for packet in route_1_devices if packet.zbee_nwk.dst not in self.devices['ZED']}
            except:
                pass
            finally:
                route_1_devices.close()
                
            for zr in potential_zr:
                displayfilter = f"(wpan.cmd == 0x04) && (wpan.src16 == {zr})"
                zr_devices = pyshark.FileCapture(pcapfile, display_filter=displayfilter)

                if not len(zr_devices):
                    self.devices['ZR'].add(zr)

            route_1_devices.close()
        except:
            pass
        #
        ## END
        try:
            self.devices['ZR'].remove(None)
            self.devices['ZED'].remove(None)
        except:
            pass

        return self.devices

    def add_device_type_to_data(self, devices=None):
        self.devices = devices if devices else self.devices
        self.df['Src_device'] = self.df['Source'].apply(lambda x:self.set_device(x))
        self.df['Dst_device'] = self.df['Destination'].apply(lambda x:self.set_device(x))

        return self.df

    def get_all_devices(self, pcapfile):

        try:
            display_filter = 'zbee_nwk.frame_type == 0'
            pcap = pyshark.FileCapture(pcapfile, display_filter=display_filter)

            addresses = set()
            manufacturer_mac_addr = {
                                        'Address': [],
                                        'MAC': [],
                                        'Manufacturer': []
                                    }

            for packet in pcap:
                src_address = packet.zbee_nwk.src
                mac = packet.zbee_nwk.zbee_sec_src64

                if "0x00000000" == src_address or any(src_address == addr for addr in self.broadcast_addresses):
                    continue

                addresses.add(packet.zbee_nwk.src)
                addresses.add(packet.zbee_nwk.dst)

                if src_address not in manufacturer_mac_addr['Address']:
                    manufacturer_mac_addr['Address'].append(src_address)
                    manufacturer_mac_addr['MAC'].append(mac)
                    try:
                        manufacturer_mac_addr['Manufacturer'].append(EUI(mac).oui.registration().org)
                    except:
                        manufacturer_mac_addr['Manufacturer'].append("")

            for addr in self.broadcast_addresses + ['0x00000000']:
                if addr in addresses:
                    addresses.remove(addr)


        except:
            pass
        finally:
            pcap.close()

        return addresses, manufacturer_mac_addr
    
    # NOTE: This function is deparacated and is not in use
    def get_data_request_difference(self, pcapfile=None):

        if self.pcapfile:
            self.pcapfile = self.pcapfile

        try:
            self.devices
            self.pcapfile
        except Exception as e:
            print("Please run the 'fetch_device_types' function first...")
            return

        displayfilter = "wpan.cmd == 0x04"
        data_req = pyshark.FileCapture(self.pcapfile, display_filter=displayfilter)

        data_requests = {
                            'Timestamp': [int(float(packet.frame_info.time_epoch)) for packet in data_req],
                            'Source': [ packet.wpan.src16
                                        if 'src16' in packet.wpan.field_names
                                        else None
                                        for packet in data_req],
                        }

        data_requests_df = pd.DataFrame(data_requests)


        data_requests_diff = data_requests_df   .groupby('Source') \
                                                .Timestamp \
                                                .apply(lambda group: 
                                                group[group.diff() > 1].sort_values(ascending=True).diff().mean())

        return data_requests_diff
