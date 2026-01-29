import socket
import time
from queue import Queue
import random

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
        self.end = (self.end - 1) % self.size
        return True
    
    def set_global_loss_probability(p: float):
        global loss_probability
        loss_probability = p
    
    def loss_filter(seq: int) -> bool:
        global loss_probability
        try:
            return random.random() < loss_probability
        except:
            return False
            
    def generate_synthetic_data(size: int) -> bytes:
        return bytes([i % 256 for i in range(size)])
