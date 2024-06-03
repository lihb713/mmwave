import json
import math
import mmap
from queue import Queue

import numpy as np
import ctypes as ct
import libpcap as pcap
import struct
import socket
from dca1000Reader.Sniff import *

class Dca1000ReaderCfg:

    def __init__(self, cfgFilePath):
        self.__loadCfg(cfgFilePath)

    def __loadCfg(self, cfgFilePath):

        with open(cfgFilePath, "r") as cfgFile:
            cfg = json.load(cfgFile)

        # data parameters
        self.txNum = cfg['dataParams']['txNum']
        self.rxNum = cfg['dataParams']['rxNum']
        self.sampleNum = cfg['dataParams']['sampleNum']
        self.chirpNum = cfg['dataParams']['chirpNum']
        self.format = cfg['dataParams']['format']

        # connection parameter
        self.localIP = cfg['connParams']['localIP']
        self.netMask = cfg['connParams']['netMask']
        self.dataPort = cfg['connParams']['dataPort']

        # dca packet parameters
        self.dcaPacketPyloadSize = cfg['dcaPacketParams']['dcaPacketPyloadSize']
        self.dcaPacketHeaderSize = cfg['dcaPacketParams']['dcaPacketHeaderSize']

        ''' packet bytes parameters '''
        # itemType: Assuming all data types are int16
        self.itemType = np.dtype(np.int16)
        self.itemSize = self.itemType.itemsize

        # frameSize: Number of bytes in a frame
        self.frameSize = self.txNum * self.chirpNum * self.rxNum * self.sampleNum * self.itemSize * self.format

        # packetSize: Number of bytes in a packet
        self.packetSize = self.dcaPacketPyloadSize + self.dcaPacketHeaderSize

class Dca1000Reader:

    def __init__(self, cfgFilePath):
        self.cfg = Dca1000ReaderCfg(cfgFilePath)
        self.handle = self.__getDataHandle()

    def __getDataHandle(self):

        ''' Get all network devices '''
        allDevs = ct.POINTER(pcap.pcap_if_t)()
        errBuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        pcap.findalldevs(ct.byref(allDevs), errBuf)
        if not allDevs:
            raise Exception(errBuf.value.decode("utf-8"))

        ''' Iterate to find configured devices '''
        dev = ct.POINTER(pcap.pcap_if_t)(allDevs)
        devName = None
        devNet = pcap.bpf_u_int32()
        devMask = pcap.bpf_u_int32()


        # Get the configured device network number
        devNetCfg = struct.unpack('<I', socket.inet_aton(self.cfg.localIP))[0] \
                    & struct.unpack('<I', socket.inet_aton(self.cfg.netMask))[0]

        while dev:

            devDesp = dev.contents.description
            print(devDesp)

            if dev.contents.name:
                # Get device name
                devName = ct.create_string_buffer(dev.contents.name)

                # Get the device network number and mask
                ret = pcap.lookupnet(devName, ct.byref(devNet), ct.byref(devMask), errBuf)
                if ret == pcap.PCAP_ERROR:
                    raise Exception(errBuf.value.decode("utf-8"))

                if devNet.value == devNetCfg:
                    break

            dev = dev.contents.next

        if devName is None:
            raise Exception("Can't find the configured device")


        ''' Get network interface handle and activate '''
        handle = pcap.create(devName, errBuf)
        if not handle:
            raise Exception(errBuf.value.decode("utf-8"))

        ret = pcap.activate(handle)
        if ret < 0:
            raise Exception(pcap.geterr(handle).decode("utf-8"))

        ''' Setting up filters '''
        expr = 'port 4098'.encode("utf-8")
        fp = pcap.bpf_program()
        ret = pcap.compile(handle, ct.byref(fp), expr, 1, devMask)
        if ret == pcap.PCAP_ERROR:
            raise Exception(pcap.geterr(handle).decode("utf-8"))

        ret = pcap.setfilter(handle, ct.byref(fp))
        if ret == pcap.PCAP_ERROR:
            raise Exception(pcap.geterr(handle).decode("utf-8"))

        return handle

class MmapFile:

    def __init__(self, dataFilePath, size):

        dataFile = open(dataFilePath, 'w+b')
        self.mmFile = mmap.mmap(dataFile.fileno(), size)
        self.mmFileMaxSize = size
        self.mmFileSize = 0
        dataFile.close()

    def write(self, data):
        dataSize = len(data)
        if self.mmFileSize + dataSize > self.mmFileMaxSize:
            self.mmFileMaxSize *= 2
            self.resize(self.mmFileMaxSize)

        writeSize = self.mmFile.write(data)
        if writeSize != dataSize:
            raise AssertionError("MmapFile.write: Incomplete writing of the given data")
        self.mmFileSize += dataSize

    def resize(self, size):
        self.mmFile.resize(size)

    def close(self):
        self.mmFile.close()

    
class Dca1000ReaderForFile(Dca1000Reader):

    def __init__(self, cfgFilePath = './dca1000Reader/Dca1000ReaderCfg.json'):
        super().__init__(cfgFilePath)

    def __readPacket(self, user, h, bytes):

        # Get eth head
        # ethHeaderPtr = ct.cast(bytes, ct.POINTER(sniffEthernet))

        # Get ip head
        ipHeaderPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN), ct.POINTER(SniffIp))
        ipHeader = ipHeaderPtr.contents
        ipHeaderLen = IP_HL(ipHeader) * 4

        assert ipHeaderLen >= 20, "Invalid IP header length"

        # Get udp head
        # udpHeaderPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN + ipHeaderLen), ct.POINTER(sniffUdp))
        # udpHeader = udpHeaderPtr.contents
        # udpSize = socket.ntohs(udpHeader.udpLen)

        # Get pyload
        pyloadPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN + ipHeaderLen + UDP_HEADER_LEN),
                            ct.POINTER(ct.c_ubyte))
        pyloadLen = socket.ntohs(ipHeader.ipLen) - (ipHeaderLen + UDP_HEADER_LEN)

        # Write pyload to bin file
        if pyloadLen > 0:
            self.mmapFile.write(ct.string_at(ct.cast(pyloadPtr, ct.c_void_p).value, pyloadLen))
            self.packetCnt += 1

        if self.packetCnt >= self.numPacketsToRead:
            pcap.breakloop(self.handle)

    def read(self, dataFilePath, numFramesToRead):

        # Create mmap
        self.mmapFile = MmapFile(dataFilePath, self.cfg.packetSize)
        self.packetCnt = 0
        self.numPacketsToRead = math.ceil(numFramesToRead * self.cfg.frameSize / self.cfg.dcaPacketPyloadSize)

        # Call pcap_loop loop to capture data
        pcapLoopFuncType = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))
        pcapLoopFunc = pcapLoopFuncType(self.__readPacket)
        pcap.loop(self.handle, -1, pcapLoopFunc, None)

        # Truncate the data file
        self.mmapFile.resize(self.mmapFile.mmFileSize)
        self.mmapFile.close()

class Dca1000ReaderForRealTime(Dca1000Reader):

    def __init__(self, cfgFilePath = './dca1000Reader/Dca1000ReaderCfg.json'):
        super().__init__(cfgFilePath)

    def __readPacket(self, user, h, bytes):

        # Get eth head
        # ethHeaderPtr = ct.cast(bytes, ct.POINTER(sniffEthernet))

        # Get ip head
        ipHeaderPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN), ct.POINTER(SniffIp))
        ipHeader = ipHeaderPtr.contents
        ipHeaderLen = IP_HL(ipHeader) * 4

        assert ipHeaderLen >= 20, "Invalid IP header length"

        # Get udp head
        # udpHeaderPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN + ipHeaderLen), ct.POINTER(sniffUdp))
        # udpHeader = udpHeaderPtr.contents
        # udpSize = socket.ntohs(udpHeader.udpLen)

        # Get pyload
        pyloadPtr = ct.cast(ct.byref(bytes.contents, ETHER_HEADER_LEN + ipHeaderLen + UDP_HEADER_LEN),
                            ct.POINTER(ct.c_ubyte))
        pyloadLen = socket.ntohs(ipHeader.ipLen) - (ipHeaderLen + UDP_HEADER_LEN)

        # Write pyload to bin file
        if pyloadLen > 0:
            self.packetQueue.put(ct.string_at(ct.cast(pyloadPtr, ct.c_void_p).value, pyloadLen))
            self.packetEvent.set()
            self.packetCnt += 1

        if self.packetCnt >= self.numPacketsToRead:
            pcap.breakloop(self.handle)

    def read(self, packetQueue, packetEvent, numFramesToRead):

        # Create a queue to hold packets
        self.packetQueue = packetQueue
        self.packetEvent = packetEvent
        self.packetCnt = 0
        self.numPacketsToRead = math.ceil(numFramesToRead * self.cfg.frameSize / self.cfg.dcaPacketPyloadSize)

        # Call pcap_loop loop to capture data
        pcapLoopFuncType = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))
        pcapLoopFunc = pcapLoopFuncType(self.__readPacket)
        pcap.loop(self.handle, -1, pcapLoopFunc, None)