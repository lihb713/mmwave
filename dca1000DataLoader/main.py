from dca1000Reader.Dca1000Reader import Dca1000ReaderForRealTime
from dataLoader.DataLoader import DataLoaderForRealTime
import numpy as np

reader = Dca1000ReaderForRealTime()
load = DataLoaderForRealTime()
loader = load.loader(reader, 300)

frames = []
for frame in loader:
    frames.append(frame)
    print(frame.shape)

frames = np.array(frames)
np.save("data.npy", frames)
