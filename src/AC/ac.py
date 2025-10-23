# Simple AC Implementation
# Based on: https://carshen.github.io/data-structures/algorithms/2014/04/07/aho-corasick-implementation-in-python.html
# But I wanted to use a dict & OOP approach so I changed it a bit
#
# https://rosettacode.org/wiki/Aho%E2%80%93Corasick_algorithm
# Actually maybe ^ has a better implementation lmao
#
# TODO: implement case sensitive matching?

from collections import deque, defaultdict
from typing import List, Dict, Optional
import sys
import time
import tracemalloc

class AhoCorasick:
    """Simple Aho-Corasick automaton for multi-pattern string matching"""
    
    def __init__(self):
        self.trie = []
        self.create_empty_trie()
    
    def create_empty_trie(self):
        """Initialize the root of the trie"""
        self.trie.append({
            'value': '',
            'next_states': {},
            'fail_state': 0,
            'output': []
        })
    
    def find_next_state(self, current_state: int, value: str) -> Optional[int]:
        """Find the next state for a given character (O(1) lookup)"""
        return self.trie[current_state]["next_states"].get(value)
    
    def add_pattern(self, pattern: str):
        """Add a pattern to the automaton"""
        current_state = 0
        j = 0
        pattern = pattern.lower()
        
        # Follow existing path as far as possible
        child = self.find_next_state(current_state, pattern[j])
        while child is not None:
            current_state = child
            j += 1
            if j < len(pattern):
                child = self.find_next_state(current_state, pattern[j])
            else:
                break
        
        # Create new states for remaning characters
        for i in range(j, len(pattern)):
            node = {
                'value': pattern[i],
                'next_states': {},
                'fail_state': 0,
                'output': []
            }
            self.trie.append(node)
            new_state_id = len(self.trie) - 1
            self.trie[current_state]["next_states"][pattern[i]] = new_state_id
            current_state = new_state_id
        
        # Mark this as an output state
        self.trie[current_state]["output"].append(pattern)
    
    def build(self):
        """Build failure links using BFS"""
        q = deque()
        
        # Nodes at level 1
        for node in self.trie[0]["next_states"].values():
            q.append(node)
            self.trie[node]["fail_state"] = 0
        
        # BFS computes failure links
        while q:
            current = q.popleft()
            
            for char, child in self.trie[current]["next_states"].items():
                q.append(child)
                
                # Find failure state
                fail_state = self.trie[current]["fail_state"]
                while self.find_next_state(fail_state, char) is None and fail_state != 0:
                    fail_state = self.trie[fail_state]["fail_state"]
                
                # Set failure link
                next_fail = self.find_next_state(fail_state, char)
                self.trie[child]["fail_state"] = next_fail if next_fail is not None else 0
                
                # Combine outputs from failure state
                self.trie[child]["output"] = (
                    self.trie[child]["output"] + 
                    self.trie[self.trie[child]["fail_state"]]["output"]
                )
    
    def search(self, text: str) -> List[Dict[str, any]]:
        """
        Searches for all patern occurrences in text
        Returns list of dicts with index and matching word
        """
        text = text.lower()
        current_state = 0
        results = []
        
        for i, char in enumerate(text):
            # Follow failure links until we find a match or reach root
            while self.find_next_state(current_state, char) is None and current_state != 0:
                current_state = self.trie[current_state]["fail_state"]
            
            # Try to transition
            current_state = self.find_next_state(current_state, char)
            if current_state is None:
                current_state = 0
            else:
                # Report all matches at this position
                for pattern in self.trie[current_state]["output"]:
                    results.append({
                        "index": i - len(pattern) + 1,
                        "word": pattern
                    })
        
        return results

def measure_performance(ac, text):
    """Measure time and memory usage of search operation"""
    tracemalloc.start()
    baseline_memory = tracemalloc.get_traced_memory()[0]
    
    # Measure search time
    start_time = time.perf_counter()
    results = ac.search(text)
    end_time = time.perf_counter()

    curr_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    search_time = (end_time - start_time) * 1000
    memory_used = (peak_memory - baseline_memory) / 1024
    
    return results, search_time, memory_used

if __name__ == "__main__":
    ac = AhoCorasick()
    patterns = ["cash", "shew", "ew", "no", "dont"]

    print(f"Patterns: {patterns}")

    for pattern in patterns:
        ac.add_pattern(pattern)
    
    ac.build()
    
    text = "cashew"
    print(f"Text: '{text}'")
    results = ac.search(text)
    print(f"Matches: {results}")

    results, search_time, memory_used = measure_performance(ac, text) 
    print(f"Search Time: {search_time:.2f} ms") 
    print(f"Memory Used: {memory_used:.2f} kb") 

    """ 
    Placeholder for parsing files instead? (Not tested)
    pattern.txt = sys.argv[1]
    text.txt = sys.argv[2]

    # Read pattern file
    try:
        with open(pattern_file, 'r') as f:
            patterns = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading pattern file: {e}")
        return
    
    # Read text file
    try:
        with open(text_file, 'r') as f:
            text = f.read()
    except Exception as e:
        print(f"Error reading pattern file: {e}")
        return
    
    # Build autmaton
    build_start = time.perf_counter()
    ac = AhoCorasick()
    for pattern in patterns:
        ac.add_pattern(pattern)
    ac.build()
    
    # Search and measure
    results, search_time, memory_used = measure_performance(ac, text)
    print(f"Found {len(results)} matches:")
    
    # Group matches by pattern
    matches = defaultdict(list)
    for match in results:
        matches[match['word']].append(match['index'])
    
    for pattern, index in matches.items():
        print(f"Pattern '{pattern}' found at index: {index}")

    print(f"Search Time: {search_time:.2f} ms") 
    print(f"Memory Used: {memory_used:.2f} kb") 
    """