import sys
import typing
from collections import Counter
import datetime
from pathlib import Path
import re
import os

import tspacketparser


class SDTService(typing.NamedTuple):
    service_id: int
    eit_user_defined_flags: int
    eit_schedule_flag: int
    eit_present_following_flag: int
    running_status: int
    free_CA_mode: int
    descriptors_loop_length: int
    descriptors_loop: bytes


class SDT(typing.NamedTuple):
    transport_stream_id: int
    version_number: int
    current_next_indicator: bool
    section_number: int
    last_section_number: int
    original_network_id: int
    services: typing.Sequence[SDTService]


class Descriptor(typing.NamedTuple):
    descriptor_tag: int
    descriptor_length: int


class RawDescriptor(typing.NamedTuple):
    descriptor_tag: int
    descriptor_length: int
    payload: bytes


class ServiceDescriptor(typing.NamedTuple):
    descriptor_tag: int
    descriptor_length: int
    service_type: int
    service_provider_name: bytes
    service_name: bytes


class BytesParser:
    def __init__(self, buffer):
        self.buffer = buffer
        self.bytepos = 0
        self.bitpos = 0
    
    def get_bytes(self, n_bytes):
        if self.bitpos != 0:
            raise RuntimeError()
        
        if self.bytepos + n_bytes > len(self.buffer):
            raise OverflowError()
        ret = self.buffer[self.bytepos:self.bytepos+n_bytes]
        self.bytepos += n_bytes
        return ret
    
    def get_int(self, n_bits):
        startbytepos = self.bytepos
        startbitpos = self.bitpos
        endbitpos = startbitpos + n_bits
        endbytepos = startbytepos + endbitpos // 8
        endbitpos = endbitpos % 8
        if endbitpos == 0:
            endbytepos -= 1
            endbitpos = 8

        startbyte = self.buffer[startbytepos] & (2**(8 - startbitpos) - 1)
        ret = startbyte
        for pos in range(startbytepos + 1, endbytepos + 1):
            ret = (ret << 8) | self.buffer[pos]
        ret >>= (8 - endbitpos)

        self.skip(n_bits)
        return ret

    def skip(self, n_bits):
        bitpos = self.bitpos + n_bits
        self.bytepos += bitpos // 8
        self.bitpos = bitpos % 8


def parse_descriptors_loop(buffer):
    bytes_parser = BytesParser(buffer)
    descriptors = []
    while bytes_parser.bytepos < len(bytes_parser.buffer):
        descriptor_tag = bytes_parser.get_int(8)
        descriptor_length = bytes_parser.get_int(8)
        payload = bytes_parser.get_bytes(descriptor_length)

        if descriptor_tag == 0x48:
            payload_parser = BytesParser(payload)
            service_type = payload_parser.get_int(8)
            service_provider_name_length = payload_parser.get_int(8)
            service_provider_name = \
                payload_parser.get_bytes(service_provider_name_length)
            service_name_length = payload_parser.get_int(8)
            service_name = payload_parser.get_bytes(service_name_length)
            descriptor = ServiceDescriptor(
                descriptor_tag, descriptor_length,
                service_type, service_provider_name, service_name,
            )
        else:
            descriptor = RawDescriptor(
                descriptor_tag, descriptor_length, payload,
            )

        descriptors.append(descriptor)
    return descriptors


def parse_sdt(buffer):
    buf = BytesParser(buffer)

    transport_stream_id = buf.get_int(16)
    buf.skip(2)
    version_number = buf.get_int(5)
    current_next_indicator = bool(buf.get_int(1))
    section_number = buf.get_int(8)
    last_section_number = buf.get_int(8)
    original_network_id = buf.get_int(16)
    buf.skip(8)

    services = []
    while buf.bytepos + 4 < len(buffer):
        service_id = buf.get_int(16)
        buf.skip(3)
        eit_user_defined_flags = buf.get_int(3)        
        eit_schedule_flag = buf.get_int(1)
        eit_present_following_flag = buf.get_int(1)
        running_status  = buf.get_int(3)
        free_CA_mode = buf.get_int(1)
        descriptors_loop_length = buf.get_int(12)
        descriptors_loop = buf.get_bytes(descriptors_loop_length)

        services.append(SDTService(
            service_id, eit_user_defined_flags, eit_schedule_flag,
            eit_present_following_flag, running_status, free_CA_mode,
            descriptors_loop_length, descriptors_loop,
        ))
    return SDT(
        transport_stream_id, version_number, current_next_indicator,
        section_number, last_section_number, original_network_id, services,
    )


class NIDSIDExtractor(tspacketparser.SectionPacketProcessor):
    def __init__(self):
        super().__init__(0x11)
        self.network_id = None
        self.service_id = None

    def feed_section(self, section):
        if section.table_id != 66:
            return

        sdt = parse_sdt(section.payload)
        network_id = sdt.original_network_id
        service_ids = [
            service.service_id for service in sdt.services
            if any(x.descriptor_tag == 72 and x.service_type == 1
                   for x in parse_descriptors_loop(service.descriptors_loop))
        ]
        if not service_ids:
            return
        service_id = min(service_ids)

        self.network_id = network_id
        self.service_id = service_id

    @property
    def done(self):
        return self.network_id is not None and self.service_id is not None


class TOTExtractor(tspacketparser.SectionPacketProcessor):
    def __init__(self):
        super().__init__(0x14)
        self.time = None

    def feed_section(self, section):
        jst_time = section.payload[:5]
        mjd = int.from_bytes(jst_time[:2], 'big')
        y_prime = int((mjd - 15078.2) / 365.25)
        m_prime = int((mjd - 14956.1 - int(y_prime * 365.25)) / 30.6001)
        d = mjd - 14956 - int(y_prime * 365.25) - int(m_prime * 30.6001)
        k = 1 if m_prime in (14, 15) else 0
        y = y_prime + k + 1900
        m = m_prime - 1 - k * 12
        hour = (jst_time[2] & 0x0f) + (jst_time[2] >> 4) * 10
        minute = (jst_time[3] & 0x0f) + (jst_time[3] >> 4) * 10
        second = (jst_time[4] & 0x0f) + (jst_time[4] >> 4) * 10

        dt = datetime.datetime(y, m, d, hour, minute, second)
        self.time = dt

    @property
    def done(self):
        # return False
        return self.time is not None


def main(argv):
    filenamepattern = re.compile(r'^[0-9]{18}-.*\.ts$')
    for filepath in argv[1:]:
        filepath = Path(filepath)
        if not filenamepattern.match(filepath.name):
            continue

        time = filepath.name[:8] + 'T' + filepath.name[8:12] + '00'
        title = filepath.stem[19:]
        
        nidsid_extractor = NIDSIDExtractor()
        # tot_extractor = TOTExtractor()
        with open(filepath, 'rb') as f:
            tspacketparser.parse(f, (nidsid_extractor,))
            # for i, packet in enumerate(read_ts_packet(f)):
                # if packet.adaptation_field:
                #     adaptation_field = parse_adaptation_field(
                #         packet.adaptation_field)

        if not nidsid_extractor.done:
            continue
        chid = format(
            nidsid_extractor.network_id * 100000 + nidsid_extractor.service_id,
            '010'
        )

        newfilename = f'{time}-{chid}-{title}.m2ts'
        newfilepath = filepath.with_name(newfilename)
        print(f'Rename "{filepath}" to "{newfilepath}"')
        os.rename(filepath, newfilepath)


if __name__ == '__main__':
    main(sys.argv)
