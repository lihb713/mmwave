import json
import math
import mmap
import os
import struct
from queue import Queue
from threading import Event, Thread

import numpy as np
from dca1000Reader.Dca1000Reader import Dca1000ReaderForRealTime

class DataLoader:

    def __init__(self, cfgFilePath):
        self.__loadCfg(cfgFilePath)

    def __loadCfg(self, cfgFilePath):

        with open(cfgFilePath, "r") as cfgFile:
            cfg = json.load(cfgFile)

        # Data format parameters
        self.txNum = cfg['dataFormatParams']['txNum']
        self.rxNum = cfg['dataFormatParams']['rxNum']
        self.sampleNum = cfg['dataFormatParams']['sampleNum']
        self.chirpNum = cfg['dataFormatParams']['chirpNum']
        self.format = cfg['dataFormatParams']['format']

        # Packet Format Parameters
        self.packetPyloadSize = cfg['packetFormatParams']['pyloadSize']
        self.packetHeaderSize = cfg['packetFormatParams']['headerSize']


        # itemType: Assuming all data types are int16
        self.itemType = np.dtype(np.int16)
        self.itemSize = self.itemType.itemsize

        # frameSize: Number of bytes in a frame
        self.frameSize = self.txNum * self.chirpNum * self.rxNum * self.sampleNum * self.itemSize * self.format
        # frameItemNum: Number of item in a frame
        self.frameItemNum = self.frameSize // self.itemSize

        # packetItemNum: Number of data in a packet
        self.packetItemNum = self.packetPyloadSize // self.itemSize
        self.packetSize = self.packetPyloadSize + self.packetHeaderSize

    def organizeFrame(self, rawFrame):

        frame = np.zeros(len(rawFrame) // 2, dtype=complex)
        # Separate IQ data
        frame[0::2] = rawFrame[0::4] + 1j * rawFrame[2::4]
        frame[1::2] = rawFrame[1::4] + 1j * rawFrame[3::4]
        return frame.reshape((self.chirpNum * self.txNum, self.rxNum, self.sampleNum))


class DataLoader_RawFrames(DataLoader):

    def __init__(self, cfgFilePath = './dataLoader/DataLoaderCfg.json'):
        super().__init__(cfgFilePath)

    def loader(self, dataFilePath):

        frames = np.fromfile(dataFilePath, dtype=self.itemType)
        if frames.size*self.itemSize % self.frameSize != 0:
            raise AssertionError("DataLoader.loaderForFile_TI: File size is not divisible by frame data size, check configuration")
        frameNum = frames.size*self.itemSize // self.frameSize
        frames = frames.reshape(frameNum, -1)
        frames = np.apply_along_axis(self.organizeFrame, 1, frames)
        for frame in frames:
            yield frame



class DataLoader_Packets(DataLoader):

    def __init__(self, cfgFilePath):
        super().__init__(cfgFilePath)

        # prePacketNo: Previous packet No.
        # Used to determine whether the packet is consecutive or not
        self.prePacketNo = -1
        # If the current frame doesn't fetch all the packet data,
        # it puts the remaining data in packetBuf
        self.packetDataBuf = None
        # rawFrameIndex: Index of the Item to be filled by the current rawFrame
        self.rawFrameIdx = 0
        self.isCompleteFrame = False
        # rawFrame: Unformatted frame data
        self.rawFrame = np.zeros(self.frameItemNum, dtype=self.itemType)

    def parsePacket(self, packet):

        self.isCompleteFrame = False

        packetNo = struct.unpack('<1l', packet[:4])[0]
        bytesNo = struct.unpack('>Q', b'\x00\x00' + packet[4:10][::-1])[0]
        packetData = np.frombuffer(packet[10:], dtype=self.itemType)

        if self.prePacketNo != -1 and self.prePacketNo != packetNo - 1:
            # raise AssertionError("DataLoader.__parsePacket: Packet data receive interrupt")
            print("DataLoader.__parsePacket: Packet data receive interrupt")

        self.prePacketNo = packetNo

        # For new rawFrame, the packetDataBuf is filled in first
        if self.rawFrameIdx == 0 and self.packetDataBuf is not None:
            self.rawFrame[:] = 0
            self.rawFrame[:self.packetDataBuf.size] = self.packetDataBuf
            self.rawFrameIdx += self.packetDataBuf.size

        # Fill the rawFrame with the current packetData.
        # neededItemNum: Number of items needed for the current rawFrame in the packet
        neededItemNum = self.rawFrame.size - self.rawFrameIdx
        if neededItemNum < packetData.size:
            self.rawFrame[self.rawFrameIdx: self.rawFrameIdx + self.packetItemNum] = packetData[:neededItemNum]
            self.packetDataBuf = packetData[neededItemNum:]
            self.rawFrameIdx += neededItemNum
        else:
            self.rawFrame[self.rawFrameIdx: self.rawFrameIdx + self.packetItemNum] = packetData
            self.packetDataBuf = None
            self.rawFrameIdx += packetData.size

        if self.rawFrameIdx == self.rawFrame.size:
            self.isCompleteFrame = True
            self.rawFrameIdx = 0

class DataLoaderForFile(DataLoader_Packets):

    def __init__(self, cfgFilePath='./dataLoader/DataLoaderCfg.json'):
        super().__init__(cfgFilePath)

    def loader(self, dataFilePath):

        dataFile = open(dataFilePath, "r+b")
        mmapDataFile = mmap.mmap(dataFile.fileno(), os.stat(dataFilePath).st_size)
        packetIdx = 0
        while mmapDataFile[packetIdx*self.packetSize: (packetIdx+1)*self.packetSize] != b'':
            self.parsePacket(mmapDataFile[packetIdx*self.packetSize: (packetIdx+1)*self.packetSize])
            packetIdx += 1
            if self.isCompleteFrame:
                yield self.organizeFrame(self.rawFrame)

class DataLoaderForRealTime(DataLoader_Packets):

    def __init__(self, cfgFilePath='./dataLoader/DataLoaderCfg.json'):
        super().__init__(cfgFilePath)


    def loader(self, reader, numFramesToRead):
        if not isinstance(reader, Dca1000ReaderForRealTime):
            raise AssertionError("DataLoaderForRealTime.loader: "
                                 "An object of type Dca1000ReaderForRealTime should be passed in to generate the loader")

        packetQueue = Queue()
        packetEvent = Event()
        packetEvent.clear()
        readerThread = Thread(target=reader.read, args=(packetQueue, packetEvent, numFramesToRead))
        readerThread.start()

        packetEvent.wait()
        while packetEvent.wait(timeout=5):
            while not packetQueue.empty():
                self.parsePacket(packetQueue.get())
                if self.isCompleteFrame:
                    yield self.organizeFrame(self.rawFrame)
            packetEvent.clear()
        while not packetQueue.empty():
            self.parsePacket(packetQueue.get())
            if self.isCompleteFrame:
                yield self.organizeFrame(self.rawFrame)

        readerThread.join()


