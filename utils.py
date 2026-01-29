import socket
import time
from queue import Queue

class CircularBuffer:
    
    def __init__(self, size:int):
        self.size = size
        self.buffer = [None] * size
        self.start = 0
        self.end = 0
        self.count = 0

    def put(self, item):
        if self.count == self.size:
            self.start = (self.start + 1) % self.size
        else:
            self.count += 1

        self.buffer[self.end] = item
        self.end = (self.end + 1) % self.size

    def get(self, index: int):
        if index < 0 or index >= self.size:
            return None
        return self.buffer[(self.start + index) % self.size]

    def remove(self, index: int):
        if index < 0 or index >= self.size:
            return False
        
        for i in range(index, self.count - 1):
            pos = (self.start + i) % self.size
            next_pos = (self.start + i + 1) % self.size
            self.buffer[pos] = self.buffer[next_pos]

        self.count -= 1
        self.end(self.end - 1) % self.size
        return True
