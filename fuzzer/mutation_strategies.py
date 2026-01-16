import random
import struct

class MutationStrategies:
    """
    Collection of mutation strategies for binary or text input fuzzing.
    """

    @staticmethod
    def bit_flip(data):
        """Flips a random bit in the data."""
        if not data:
            return data
        
        data_list = bytearray(data)
        idx = random.randint(0, len(data_list) - 1)
        bit_idx = random.randint(0, 7)
        data_list[idx] ^= (1 << bit_idx)
        return bytes(data_list)

    @staticmethod
    def byte_flip(data):
        """Flips a random byte in the data (XOR with 0xFF)."""
        if not data:
            return data
            
        data_list = bytearray(data)
        idx = random.randint(0, len(data_list) - 1)
        data_list[idx] ^= 0xFF
        return bytes(data_list)

    @staticmethod
    def arithmetic(data):
        """Adds or subtracts small values from a random byte."""
        if not data:
            return data
            
        data_list = bytearray(data)
        idx = random.randint(0, len(data_list) - 1)
        val = random.randint(1, 10)
        if random.choice([True, False]):
            data_list[idx] = (data_list[idx] + val) % 256
        else:
            data_list[idx] = (data_list[idx] - val) % 256
        return bytes(data_list)

    @staticmethod
    def interesting_values(data):
        """Replaces a random chunk with an 'interesting' value (int limits, etc.)."""
        if not data:
            return data
            
        # Interesting values in little-endian representation
        # 0, -1, MAX_INT, MIN_INT, etc.
        interesting_ints = [
            0, 
            0xFFFFFFFF, # -1 / MAX_UINT
            0x7FFFFFFF, # MAX_INT
            0x80000000, # MIN_INT
            0xFFFF,     # MAX_USHORT
            0x7FFF      # MAX_SHORT
        ]
        
        data_list = bytearray(data)
        if len(data_list) < 4:
            # Append if too short
            return data + struct.pack('<I', random.choice(interesting_ints))
        
        idx = random.randint(0, len(data_list) - 4)
        val = random.choice(interesting_ints)
        chunk = struct.pack('<I', val)
        
        for i in range(4):
            data_list[idx + i] = chunk[i]
            
        return bytes(data_list)

    @staticmethod
    def splice(data1, data2):
        """Combines two inputs by splicing them at a random crossover point."""
        if not data1 or not data2:
            return data1 or data2
            
        idx1 = random.randint(0, len(data1))
        idx2 = random.randint(0, len(data2))
        
        # Take head of data1 and tail of data2
        return data1[:idx1] + data2[idx2:]

    @staticmethod
    def mutate(data):
        """Applies a random mutation strategy."""
        strategies = [
            MutationStrategies.bit_flip,
            MutationStrategies.byte_flip,
            MutationStrategies.arithmetic,
            MutationStrategies.interesting_values
        ]
        strategy = random.choice(strategies)
        return strategy(data)
