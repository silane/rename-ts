import typing


__all__ = [
    'TSPacket', 'AdaptationField', 'Section', 'parse_adaptation_field',
    'PacketProcessor', 'SectionPacketProcessor', 'parse',
]

class PacketParseError(Exception):
    pass


class TSPacket(typing.NamedTuple):
    transport_error_indicator: bool
    payload_unit_start_indicator: bool
    transport_priority: bool
    pid: int
    transport_scrambling_control: int
    adaptation_field_control: int
    continuity_counter: int
    adaptation_field: bytes
    payload: bytes


class AdaptationField(typing.NamedTuple):
    discontinuity_indicator: bool
    random_access_indicator: bool
    elementary_stream_priority_indicator: bool
    pcr_flag: bool
    opcr_flag: bool
    splicing_point_flag: bool
    transport_private_data_flag: bool
    adaptation_field_extension_flag: bool
    pcr: int
    opcr: int
    splicing_countdown: int
    transport_private_data: bytes
    adaptation_field_extension: bytes


class Section(typing.NamedTuple):
    table_id: int
    section_syntax_indicator: bool
    section_length: int
    payload: bytes


class SectionParser:
    def __init__(self):
        self.buffer = None # Noneなら開始位置を見失ってる
        self.parsed_sections = []
    
    def feed(self, payload_unit_start_indicator: bool, payload: bytes) -> None:
        if self.buffer is None:
            if payload_unit_start_indicator:
                self.buffer = payload[1+payload[0]:]
            else:
                return
        else:
            if payload_unit_start_indicator:
                self.buffer += payload[1:]
            else:
                self.buffer += payload
        
        while True:
            if len(self.buffer) < 3:
                break
            table_id = self.buffer[0]
            num = int.from_bytes(self.buffer[1:3], 'big')
            section_syntax_indicator = num >> 15 != 0
            section_length = num & 0x0fff

            if len(self.buffer) < 3 + section_length:
                break
            table_body = self.buffer[3:3+section_length]
            self.parsed_sections.insert(0, Section(
                table_id, section_syntax_indicator, section_length, table_body,
            ))
            self.buffer = self.buffer[3+section_length:]

            if not self.buffer or self.buffer[0] == 0xff:
                # バッファをちょうど使い切ったか、後続がスタッフィングバイトなら
                self.buffer = None
                break
    
    def get_section(self) -> typing.Optional[Section]:
        if self.parsed_sections:
            return self.parsed_sections.pop()
        else:
            return None


def parse_adaptation_field(buffer: bytes) -> typing.Optional[AdaptationField]:
    def parse_pcr(buffer):
        num = int.from_bytes(buffer, 'big')
        return (num >> 15) * 300 + ((num >> 6) & 0x01ff)

    adaptation_field_length = buffer[0]
    if 1 + adaptation_field_length != len(buffer):
        raise PacketParseError()
    
    if adaptation_field_length == 0:
        return None
    
    discontinuity_indicator = buffer[1] >> 7 != 0
    random_access_indicator = (buffer[1] >> 6) & 0x01 != 0
    elementary_stream_priority_indicator = (buffer[1] >> 5) & 0x01 != 0
    pcr_flag = (buffer[1] >> 4) & 0x01 != 0
    opcr_flag = (buffer[1] >> 3) & 0x01 != 0
    splicing_point_flag = (buffer[1] >> 2) & 0x01 != 0
    transport_private_data_flag = (buffer[1] >> 1) & 0x01 != 0
    adaptation_field_extension_flag = buffer[1] & 0x01 != 0
    
    pointer = 2
    if pcr_flag:
        pcr = parse_pcr(buffer[pointer:pointer + 6])
        pointer += 6
    else:
        pcr = None
    if opcr_flag:
        opcr = parse_pcr(buffer[pointer:pointer + 6])
        pointer += 6
    else:
        opcr = None
    if splicing_point_flag:
        splicing_countdown = int.from_bytes(buffer[pointer:pointer + 1],
                                            'big', signed=True)
        pointer += 1
    else:
        splicing_countdown = None
    
    return AdaptationField(
        discontinuity_indicator, random_access_indicator,
        elementary_stream_priority_indicator, pcr_flag, opcr_flag,
        splicing_point_flag, transport_private_data_flag,
        adaptation_field_extension_flag, pcr, opcr, splicing_countdown,
        None, None,
    )


def parse_packet(buffer: bytes) -> TSPacket:
    header = int.from_bytes(buffer[:4], 'big')
    sync_byte = header >> 24
    transport_error_indicator = header & 0x800000 != 0
    payload_unit_start_indicator = header & 0x400000 != 0
    transport_priority = header & 0x200000 != 0
    pid = (header >> 8) & 0x1fff
    transport_scrambling_control = (header >> 6) & 0x03
    adaptation_field_control = (header >> 4) & 0x03
    continuity_counter = header & 0x0f

    adaptation_field_length = None
    if adaptation_field_control & 0x02:
        adaptation_field_length = buffer[4]

    if sync_byte != 0x47:
        raise PacketParseError()
    if transport_error_indicator:
        raise PacketParseError()
    if pid >= 0x0002 and pid <= 0x000f:
        raise PacketParseError()
    if transport_scrambling_control == 0x01:
        raise PacketParseError()
    if adaptation_field_control == 0x00:
        raise PacketParseError()
    if adaptation_field_control == 0x02 and adaptation_field_length > 183:
        raise PacketParseError()
    if adaptation_field_control == 0x03 and adaptation_field_length > 182:
        raise PacketParseError()
    
    if adaptation_field_length is not None:
        adaptation_field = buffer[4:5 + adaptation_field_length]
        payload = buffer[5 + adaptation_field_length:]
    else:
        adaptation_field = None
        payload = buffer[4:]

    if adaptation_field_control & 0x01 == 0:
        payload = None
    
    return TSPacket(
        transport_error_indicator, payload_unit_start_indicator,
        transport_priority, pid, transport_scrambling_control,
        adaptation_field_control, continuity_counter, adaptation_field, payload,
    )


def read_ts_packet(f: typing.BinaryIO) -> typing.Iterator[TSPacket]:
    SYNC_BYTE = 0x47
    TS_PACKET_SIZE = 188
    packet = b''
    while True:
        packet += f.read(TS_PACKET_SIZE - len(packet))
        if len(packet) != TS_PACKET_SIZE:
            break
        idx = packet.find(SYNC_BYTE)
        if idx == 0:
            try:
                yield parse_packet(packet)
            except PacketParseError:
                packet = packet[1:]
            else:
                packet = b''
        else:
            if idx == -1:
                idx = TS_PACKET_SIZE
            packet = packet[idx:]


class PacketProcessor:
    def feed(self, packet: TSPacket) -> None:
        raise NotImplementedError()
    @property
    def done(self) -> bool:
        return False


class SectionPacketProcessor(PacketProcessor):
    def __init__(self, pid: int):
        super().__init__()
        self.pid = pid
        self.section_parser = SectionParser()

    def feed(self, packet: TSPacket) -> None:
        if packet.pid != self.pid:
            return
        self.section_parser.feed(packet.payload_unit_start_indicator,
                                 packet.payload)
        section = self.section_parser.get_section()
        if not section:
            return
        self.feed_section(section)

    def feed_section(self, section: Section) -> None:
        raise NotImplementedError()


def parse(f: typing.BinaryIO,
          packet_processors: typing.Iterable[PacketProcessor]) -> None:
    for packet in read_ts_packet(f):
        undone_processors = [x for x in packet_processors if not x.done]
        if not undone_processors:
            break
        for packet_processor in undone_processors:
            packet_processor.feed(packet)
